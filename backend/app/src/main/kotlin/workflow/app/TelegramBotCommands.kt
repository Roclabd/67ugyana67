package workflow.app

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.annotation.PreDestroy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component
import workflow.engine.Redaction
import workflow.engine.RunStatus
import workflow.engine.securityIndex
import workflow.engine.Workflow
import workflow.nodes.DeliveryHttpFailure
import workflow.nodes.InputRejected
import workflow.nodes.TelegramAttachment
import workflow.nodes.TelegramDestination
import workflow.nodes.TelegramTransport
import workflow.nodes.findingsOf
import workflow.nodes.normalizeRepositoryInput
import workflow.nodes.telegramChats
import workflow.nodes.telegramPublicOrigin
import workflow.nodes.telegramRunCard
import workflow.nodes.validTelegramToken
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap

internal const val BOT_POLL_SECONDS = 25
internal const val BOT_MAX_MESSAGE = 4096
internal const val BOT_RUNS_PER_HOUR = 5
internal const val BOT_WORKFLOW_NAME = "Telegram: проверка репозитория по ссылке"

/**
 * Команды Telegram-бота (`/help`, `/status`, `/last`, `/run`, `/runs`) через long polling `getUpdates`.
 * Включается `TELEGRAM_BOT_COMMANDS=true`, отвечает только чатам из настроек Telegram. Исходящие запросы идут
 * через тот же [TelegramTransport] (только api.telegram.org, проверка DNS), что и уведомления.
 */
@Component
class TelegramBotCommands(
    private val settings: TelegramSettingsStore,
    private val transport: TelegramTransport,
    private val runs: RunService,
    private val history: RunStore,
    private val workflows: WorkflowStore,
    private val templates: TemplateLibrary,
    private val repositories: RepositorySettingsStore,
    private val reports: ReportService,
    private val json: ObjectMapper,
    @Value("\${TELEGRAM_BOT_COMMANDS:false}") private val enabled: Boolean,
    @Value("\${APP_PUBLIC_URL:}") publicUrl: String,
    @Value("\${workflow.data-dir:data}") private val data: String,
) {
    private val log = LoggerFactory.getLogger(TelegramBotCommands::class.java)
    private val origin = telegramPublicOrigin(publicUrl)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val activeRuns = ConcurrentHashMap.newKeySet<String>()
    private val recentRuns = ConcurrentHashMap<String, ArrayDeque<Instant>>()
    private val offsetFile: Path get() = Path.of(data).toAbsolutePath().resolve("telegram-bot-offset")

    @Volatile private var stopped = false
    @Volatile private var thread: Thread? = null
    @Volatile private var offset: Long? = null

    /** Тестовая подмена времени и пауз. */
    internal var clock: () -> Instant = Instant::now
    internal var sleeper: (Long) -> Unit = { Thread.sleep(it) }

    val polling: Boolean get() = thread?.isAlive == true
    internal val busyChats: Int get() = activeRuns.size

    @EventListener(ApplicationReadyEvent::class)
    fun start() {
        if (!enabled || thread != null) return
        stopped = false
        thread = Thread({ runPolling() }, "telegram-bot-commands").apply { isDaemon = true; start() }
        log.info("Команды Telegram-бота включены (long polling).")
    }

    @PreDestroy
    fun shutDown() {
        stopped = true
        thread?.interrupt()
        scope.cancel()
    }

    /** Цикл опроса до остановки или 409; сетевые ошибки не роняют приложение: пауза 1 -> 30 с. */
    internal fun runPolling() {
        var backoff = 1L
        while (!stopped) {
            try {
                if (!pollOnce()) {
                    sleeper(5_000)
                }
                backoff = 1
            } catch (_: InterruptedException) {
                return
            } catch (failure: DeliveryHttpFailure) {
                if (failure.status == 409) {
                    log.warn("Telegram вернул 409: для бота задан webhook. Опрос команд остановлен; снимите webhook и перезапустите сервер.")
                    stopped = true
                    return
                }
                log.warn("getUpdates: HTTP {}", failure.status)
                backoff = pause(backoff)
            } catch (_: Exception) {
                log.warn("getUpdates: ошибка сети, повтор через {} с", backoff)
                backoff = pause(backoff)
            } catch (_: Throwable) {
                backoff = pause(backoff)
            }
        }
    }

    private fun pause(seconds: Long): Long {
        try {
            sleeper(seconds * 1000)
        } catch (_: InterruptedException) {
            stopped = true
        }
        return minOf(seconds * 2, 30)
    }

    /** Один запрос getUpdates и обработка пришедших сообщений. false, если опрос не настроен (нет токена или чатов). */
    internal fun pollOnce(): Boolean {
        val defaults = settings.defaults()
        val chats = telegramChats(defaults.chatId).orEmpty()
        if (!validTelegramToken(defaults.token) || chats.isEmpty()) return false
        val current = offset ?: readOffset().also { offset = it }
        val raw = transport.updates(defaults.token, current, BOT_POLL_SECONDS)
        val body = json.readTree(raw)
        if (!body.path("ok").asBoolean(false)) {
            if (body.path("error_code").asInt() == 409) throw DeliveryHttpFailure(409)
            throw DeliveryHttpFailure(body.path("error_code").asInt(502))
        }
        var next = current
        for (update in body.path("result")) {
            val id = update.path("update_id").asLong(-1)
            if (id < 0) continue
            next = maxOf(next, id + 1)
            try {
                handle(defaults.token, chats, update.path("message"))
            } catch (failure: InterruptedException) {
                throw failure
            } catch (_: Exception) {
                log.warn("Не удалось обработать команду Telegram.")
            }
        }
        if (next != current) {
            offset = next
            writeOffset(next)
        }
        return true
    }

    private fun readOffset(): Long = runCatching { Files.readString(offsetFile).trim().toLong() }.getOrDefault(0L)

    private fun writeOffset(value: Long) {
        runCatching {
            Files.createDirectories(offsetFile.parent)
            Files.writeString(offsetFile, value.toString())
        }
    }

    private fun authorized(chats: List<String>, chat: JsonNode): Boolean {
        val id = chat.path("id").asText()
        val username = chat.path("username").textValue()?.let { "@" + it.lowercase() }
        return id in chats || (username != null && chats.any { it.lowercase() == username })
    }

    private fun handle(token: String, chats: List<String>, message: JsonNode) {
        val chat = message.path("chat")
        val text = message.path("text").textValue() ?: return
        if (!text.startsWith("/") || message.path("from").path("is_bot").asBoolean(false)) return
        if (!authorized(chats, chat)) {
            log.debug("Команда от неразрешённого чата проигнорирована.")
            return
        }
        val chatId = chat.path("id").asText()
        val parts = text.trim().split(Regex("\\s+"), limit = 2)
        val command = parts[0].removePrefix("/").substringBefore('@').lowercase()
        val argument = parts.getOrNull(1).orEmpty().trim()
        val redaction = Redaction(json, listOf(token))
        val replyTo = Reply(token, chatId, redaction)
        when (command) {
            "start", "help" -> replyTo.text(HELP)
            "status" -> replyTo.text(status())
            "last" -> last(replyTo)
            "runs" -> replyTo.text(runsList())
            "run" -> run(replyTo, argument)
            else -> replyTo.text("Неизвестная команда. Список: /help")
        }
    }

    private inner class Reply(val token: String, val chatId: String, val redaction: Redaction) {
        fun text(body: String, markup: Map<String, Any>? = null) {
            val safe = redaction.text(body)
            val limited = if (safe.length <= BOT_MAX_MESSAGE) safe else {
                val cut = safe.take(BOT_MAX_MESSAGE - 1)
                cut.substringBeforeLast('\n', cut) + "…"
            }
            val payload = buildMap<String, Any> {
                put("chat_id", chatId)
                put("parse_mode", "HTML")
                put("text", limited)
                put("link_preview_options", mapOf("is_disabled" to true))
                markup?.let { put("reply_markup", it) }
            }
            transport.message(token, json.writeValueAsString(payload))
        }

        fun document(attachment: TelegramAttachment) =
            transport.document(token, TelegramDestination(chatId), attachment)
    }

    private fun esc(value: String) = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    private fun when_(at: Instant?) = at?.let { TIME.format(it) } ?: "—"

    private fun countsLine(run: RunRecord): String {
        if (run.counts.isEmpty()) return "нет данных"
        val labels = listOf("CRITICAL" to "крит.", "HIGH" to "выс.", "MEDIUM" to "сред.", "LOW" to "низк.")
        return labels.joinToString(" · ") { (key, label) -> "$label ${run.counts[key] ?: 0}" }
    }

    private fun status(): String {
        val recent = history.list(null)
        val last = recent.firstOrNull()
        val rules = recent.asSequence().mapNotNull { rulesVersionSignature(it.rulesVersions) }.firstOrNull() ?: "—"
        return buildString {
            appendLine("<b>$PRODUCT_NAME: статус</b>")
            appendLine("Версия правил: <code>${esc(rules)}</code>")
            appendLine("Сценариев: ${workflows.list().size}")
            appendLine("Подключённых репозиториев: ${repositories.urls().size}")
            if (last == null) appendLine("Последний запуск: пока не было") else {
                appendLine("Последний запуск: ${esc(last.workflowName ?: "без названия")}")
                appendLine("Статус: ${last.status}, покрытие: ${if (last.status == RunStatus.RUNNING) "—" else last.coverageStatus}")
                appendLine("Находки: ${countsLine(last)}")
                appendLine("Время: ${when_(last.finishedAt ?: last.startedAt)}")
            }
            append("Время сервера: ${when_(clock())}")
        }
    }

    private fun runsList(): String {
        val recent = history.list(null).take(5)
        if (recent.isEmpty()) return "Запусков пока не было."
        return recent.joinToString("\n", prefix = "<b>Последние запуски</b>\n") { run ->
            "• ${esc(run.workflowName ?: "без названия")} · ${run.status} · ${countsLine(run)} · ${when_(run.finishedAt ?: run.startedAt)}"
        }
    }

    private fun last(reply: Reply) {
        val run = history.list(null).firstOrNull { it.finishedAt != null && it.status != RunStatus.RUNNING }
        if (run == null) {
            reply.text("Завершённых запусков пока нет.")
            return
        }
        sendResult(reply, run)
    }

    /** Карточка запуска (как в уведомлении Telegram) и PDF-отчёт; без PDF отправляется Markdown. */
    private fun sendResult(reply: Reply, run: RunRecord) {
        val report = run.report
        val findings = report?.let(::findingsOf).orEmpty()
        val index = if (run.coverageStatus == "COMPLETE" || findings.isNotEmpty()) {
            securityIndex(findings.groupingBy { it.path("severity").asText() }.eachCount())
        } else null
        val failure = run.error?.takeIf { run.status == RunStatus.FAILED }
        val summary = report?.path("ai")?.path("summary")?.textValue()
        val card = telegramRunCard(run.id, run.workflowName, run.coverageStatus, failure, findings, 3, index, summary) {
            reply.redaction.text(it)
        }
        val markup = origin?.let { base ->
            val runUrl = "$base/runs/${run.id}"
            mapOf("inline_keyboard" to listOf(
                if (report != null) listOf(
                    mapOf("text" to "Открыть отчёт", "url" to "$runUrl/report"),
                    mapOf("text" to "Скачать PDF", "url" to "$base/api/runs/${run.id}/report.pdf"),
                ) else listOf(mapOf("text" to "Открыть запуск", "url" to runUrl)),
            ))
        }
        reply.text(card, markup)
        if (report == null || failure != null) return
        val meta = json.createObjectNode().also { meta ->
            run.workflowName?.let { meta.put("workflowName", it) }
            run.finishedAt?.let { meta.put("finishedAt", it.toString()) }
        }
        val pdf = runCatching { reports.pdf(report, meta) }.getOrNull()
            ?.takeIf { it.size in 5..49_000_000 && String(it, 0, 4, Charsets.ISO_8859_1) == "%PDF" }
        val attachment = if (pdf != null) {
            TelegramAttachment("report-${run.id.take(8)}.pdf", "application/pdf", pdf)
        } else {
            val markdown = reply.redaction.text(reports.markdown(report))
            TelegramAttachment("report-${run.id.take(8)}.md", "text/markdown", markdown.toByteArray(Charsets.UTF_8))
        }
        reply.document(attachment)
    }

    private fun run(reply: Reply, argument: String) {
        if (argument.isEmpty()) {
            reply.text("Укажите ссылку на подключённый репозиторий: <code>/run https://github.com/owner/repo</code>")
            return
        }
        val input = normalizeRepositoryInput(argument.substringBefore(' '))
        if (input == null) {
            reply.text("Не удалось распознать ссылку. Нужна ссылка вида https://github.com/owner/repo.")
            return
        }
        // Внешний ввод: репозиторий сам не подключается, только запуск по уже подключённым.
        if (input.url !in repositories.urls()) {
            reply.text("Репозиторий не подключён. Добавьте его в приложении (раздел репозиториев), затем повторите команду.")
            return
        }
        val chat = reply.chatId
        synchronized(recentRuns) {
            if (chat in activeRuns) {
                reply.text("В этом чате уже идёт проверка. Дождитесь результата.")
                return
            }
            val now = clock()
            val times = recentRuns.getOrPut(chat) { ArrayDeque() }
            while (times.isNotEmpty() && Duration.between(times.first, now) >= Duration.ofHours(1)) times.removeFirst()
            if (times.size >= BOT_RUNS_PER_HOUR) {
                reply.text("Лимит: не более $BOT_RUNS_PER_HOUR запусков в час на чат. Попробуйте позже.")
                return
            }
            activeRuns.add(chat)
            times.addLast(now)
        }
        val ticket = try {
            val trigger = json.createObjectNode().put("kind", "manual")
            trigger.putObject("source").put("kind", "repo").put("url", input.url)
            runs.start(botWorkflow().id!!, trigger)
        } catch (failure: Exception) {
            release(chat, refund = true)
            reply.text(when (failure) {
                is Conflict -> "Все слоты заняты. Попробуйте чуть позже."
                is InputRejected -> failure.message ?: "Источник не прошёл проверку."
                else -> "Не удалось запустить проверку."
            })
            return
        }
        reply.text("Запущено: <code>${ticket.id}</code>")
        scope.launch {
            try {
                ticket.completion.await()
                sendResult(reply, history.get(ticket.id))
            } catch (_: kotlinx.coroutines.CancellationException) {
                // остановка сервера
            } catch (_: Exception) {
                runCatching { reply.text("Проверка <code>${ticket.id}</code> завершилась, но результат отправить не удалось.") }
            } finally {
                release(chat, refund = false)
            }
        }
    }

    private fun release(chat: String, refund: Boolean) {
        synchronized(recentRuns) {
            activeRuns.remove(chat)
            if (refund) recentRuns[chat]?.pollLast()
        }
    }

    /** Служебный сценарий: шаблон `release` без нод уведомлений (результат уходит в тот же чат). */
    @Synchronized
    private fun botWorkflow(): Workflow {
        workflows.list().firstOrNull { it.name == BOT_WORKFLOW_NAME }?.let { return workflows.unlocked(it.id) }
        val template = templates.get("release").workflow
        val removed = template.nodes.filter { it.type.startsWith("notify.") }.map { it.id }.toSet()
        val graph = template.copy(
            id = null, version = 0, name = BOT_WORKFLOW_NAME,
            nodes = template.nodes.filter { it.id !in removed },
            edges = template.edges.filter { it.from.node !in removed && it.to.node !in removed },
        )
        return workflows.create(graph)
    }

    companion object {
        private val TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC)
        private val HELP = """
            <b>Команды $PRODUCT_NAME</b>
            /status — версия правил, сценарии, репозитории, последний запуск
            /last — итог последней проверки и PDF-отчёт
            /run &lt;ссылка&gt; — проверить уже подключённый репозиторий
            /runs — пять последних запусков
            /help — этот список
        """.trimIndent()
    }
}
