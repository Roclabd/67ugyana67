package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import jakarta.mail.Message
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import workflow.engine.*
import java.net.URI
import java.util.Properties

private const val MAX_TELEGRAM_ATTACHMENT = 50_000_000

@Configuration(proxyBeanMethods = false)
class OutputNodes(
    private val json: ObjectMapper,
    @Value("\${TELEGRAM_BOT_TOKEN:}") private val telegramToken: String,
    @Value("\${TELEGRAM_CHAT_ID:}") private val telegramChatId: String,
    @Value("\${SMTP_HOST:}") private val smtpHost: String,
    @Value("\${SMTP_PORT:587}") private val smtpPort: Int,
    @Value("\${SMTP_USER:}") private val smtpUser: String,
    @Value("\${SMTP_PASSWORD:}") private val smtpPassword: String,
    @Value("\${SMTP_TO:}") private val smtpTo: String,
    private val exporter: ReportExporter? = null,
    @Value("\${APP_PUBLIC_URL:}") publicUrl: String = "",
    private val telegramDefaultsSource: TelegramDefaultsSource? = null,
    private val telegramHistory: TelegramRunHistory? = null,
    internal var telegramTransport: TelegramTransport = TelegramHttpTransport(),
) {
    private val publicOrigin = runCatching { URI(publicUrl.trim()) }.getOrNull()?.takeIf {
        it.scheme in setOf("https", "http") && it.host != null && it.userInfo == null &&
            it.rawPath in setOf("", "/") && it.rawQuery == null && it.rawFragment == null &&
            (it.port == -1 || it.port in 1..65535)
    }?.toASCIIString()?.trimEnd('/')
    private val spaces = Regex("\\s+")
    private val reportInputs = listOf(
        PortSpec("report", PortType.REPORT, false),
        PortSpec("findings", PortType.FINDINGS, false),
        PortSpec("explanation", PortType.ANY, false),
    )

    @Bean fun buildReport(): NodeDefinition = PlatformNode(
        "output.report", "Собрать отчёт", NodeCategory.OUTPUT,
        inputs = reportInputs, outputs = listOf(PortSpec("report", PortType.REPORT)),
    ) { ctx, input ->
        val explanation = explanation(input)
        val ai = explanation?.let { json.valueToTree<JsonNode>(it).path("ai") }
            ?.takeIf { it.path("status").asText() in setOf("OK", "PARTIAL", "NOT_RECEIVED") }
        result("report", buildMap {
            put("findings", findings(input))
            put("coverage", coverage(ctx, input))
            explanation?.let { put("explanation", ReportExplanation(ctx.redact(it.text))) }
            ai?.let { put("ai", it) }
        })
    }

    @Bean fun telegram(): NodeDefinition = PlatformNode(
        "notify.telegram", "Отправить в Telegram", NodeCategory.OUTPUT, reportInputs,
        paramsSchema = schema("""{"type":"object","properties":{
            "token":{"type":"string","maxLength":150,"format":"password"},
            "chatId":{"type":"string","maxLength":$TELEGRAM_CHAT_LIST_MAX_LENGTH},
            "attachments":{"type":"array","items":{"type":"string","enum":["pdf","md","html","json","sarif"]},
                "uniqueItems":true,"maxItems":5},
            "format":{"type":"string","enum":["pdf","md","html","json","sarif","none"]},
            "minSeverity":{"type":"string","enum":["always","LOW","MEDIUM","HIGH","CRITICAL"],"default":"always"},
            "onlyNew":{"type":"boolean","default":false},
            "topN":{"type":"integer","enum":[3,5,10],"default":3},
            "includeAi":{"type":"boolean","default":true},
            "includeIndex":{"type":"boolean","default":false},
            "silent":{"type":"boolean","default":false},
            "threadId":{"type":"integer","minimum":1,"maximum":2147483647},
            "language":{"type":"string","enum":["ru","en"],"default":"ru"}
        },"additionalProperties":false}"""),
        secretParams = setOf("token"), notifyOnFailure = true,
    ) { ctx, input ->
        withContext(Dispatchers.IO) { NodeOutput(emptyMap(), sendTelegram(ctx, input)) }
    }

    private suspend fun sendTelegram(ctx: NodeContext, input: NodeInput): NodeStatus {
        val params = ctx.params
        val all = findings(input)
        val onlyNew = params.path("onlyNew").asBoolean()
        val previous = if (ctx.failureReason == null && (onlyNew || publicOrigin != null)) {
            telegramHistory?.previous(ctx.runId, all.takeIf { onlyNew })
        } else null
        val selected = if (onlyNew && previous != null) previous.added else all
        val threshold = telegramSeverityRanks[params.path("minSeverity").asText()]
        if (threshold != null && selected.none { (telegramSeverityRanks[it.path("severity").asText()] ?: Int.MAX_VALUE) <= threshold }) {
            ctx.log("Telegram: уведомление пропущено по порогу.")
            return NodeStatus.SKIPPED
        }
        if (onlyNew && selected.isEmpty() && ctx.failureReason == null && (previous != null || ctx.coverageStatus == "COMPLETE")) {
            ctx.log("Telegram: уведомление пропущено, новых находок нет.")
            return NodeStatus.SKIPPED
        }

        val defaults = telegramDefaultsSource?.defaults()
        val token = params.path("token").asText().takeIf(String::isNotBlank) ?: defaults?.token ?: telegramToken
        val chat = params.path("chatId").asText().takeIf(String::isNotBlank) ?: defaults?.chatId ?: telegramChatId
        val chats = telegramChats(chat)
        if (!validTelegramToken(token) || chats == null) {
            throw NodeFailure("Для уведомления Telegram укажите токен бота и список ID чатов через запятую.")
        }
        val formats = TelegramFormat.fromParams(params) ?: defaults?.attachments ?: listOf(TelegramFormat.PDF)
        val silent = params.path("silent").asBoolean()
        val threadId = params.path("threadId").takeIf { it.isIntegralNumber }?.asInt()
        val destinations = chats.map { TelegramDestination(it, threadId, silent) }
        val includeAi = params.path("includeAi").asBoolean(true) && selected.size == all.size
        val incomingAi = if (includeAi) {
            json.valueToTree<JsonNode>(input.ports["report"]).path("ai").takeIf { it.isObject }
                ?: explanation(input)?.let { json.valueToTree<JsonNode>(it).path("ai").takeIf { ai -> ai.isObject } }
        } else null
        val options = TelegramCardOptions(
            english = params.path("language").asText() == "en",
            topN = params.path("topN").asInt(3),
            onlyNew = onlyNew,
            aiSummary = if (includeAi) incomingAi?.path("summary")?.textValue() ?: explanation(input)?.text else null,
            index = if (params.path("includeIndex").asBoolean() && (ctx.coverageStatus == "COMPLETE" || all.isNotEmpty())) {
                securityIndex(all.groupingBy { it.path("severity").asText() }.eachCount())
            } else null,
        )
        val redact: (String) -> String = { value ->
            deliveryText(ctx, value).replace(token, Redaction.MASK)
                .let { safe -> defaults?.token?.takeIf(String::isNotBlank)?.let { safe.replace(it, Redaction.MASK) } ?: safe }
        }
        val text = telegramPriorityCard(ctx, selected, telegramGaps(ctx, input), options, redact)
        val retryBudget = java.util.concurrent.atomic.AtomicLong(TELEGRAM_RETRY_BUDGET_MS)
        val cards = sendTelegramBatch(destinations, retryBudget) { destination ->
            telegramTransport.message(token, json.writeValueAsString(
                telegramPayload(ctx, destination, text, options, previous?.runId),
            ))
        }
        val delivered = cards.sent
        if (delivered.isEmpty()) {
            val reason = when {
                cards.failure == null -> "истекло время доставки"
                (cards.failure as? DeliveryHttpFailure)?.status == 429 -> "Telegram ограничил частоту отправки"
                else -> "сервис недоступен или отклонил запрос"
            }
            throw NodeFailure("Telegram: карточка не отправлена, $reason.")
        }

        val failedNames = linkedSetOf<String>()
        var failedSends = 0
        if (ctx.failureReason == null && formats.isNotEmpty()) {
            val files = runCatching {
                val report = telegramReport(ctx, input, selected, incomingAi, redact)
                val explanation = explanation(input)?.text?.takeIf { includeAi }?.let(redact)
                formats.mapNotNull { format -> telegramFile(ctx, report, explanation, format, formats, redact) }
            }.getOrElse { formats.map { it to null } }
            files.filter { it.second == null }.forEach { failedNames += it.first.value }
            val ready = files.mapNotNull { (format, file) -> file?.let { format to it } }
            failedSends = failedNames.size * delivered.size
            for ((format, file) in ready) {
                val sentFiles = sendTelegramBatch(delivered, retryBudget) { destination ->
                    telegramTransport.document(token, destination, file)
                }
                val failed = delivered.size - sentFiles.sent.size
                if (failed > 0) {
                    failedNames += format.value
                    failedSends += failed
                }
            }
        }
        if (destinations.size == 1 && failedSends != 0) {
            throw NodeFailure("Telegram: карточка отправлена, не доставлены файлы отчёта: ${failedNames.joinToString(", ")}.")
        }
        if (delivered.size != destinations.size || failedSends != 0) {
            val summary = "Telegram: карточка отправлена в ${delivered.size} из ${destinations.size} чатов."
            val fileError = if (failedSends == 0) "" else
                " Не удалось доставить файлы отчёта (${failedNames.joinToString(", ")}): $failedSends."
            throw NodeFailure(summary + fileError)
        }
        return NodeStatus.SUCCESS
    }

    @Bean fun webhook(): NodeDefinition = notification(
        "webhook", "Отправить на HTTPS-вебхук",
        """{"type":"object","properties":{"url":{"type":"string","maxLength":500},
            "token":{"type":"string","maxLength":300}},"required":["url"],"additionalProperties":false}""", setOf("token"),
    ) { ctx, input ->
        val content = deliveryText(ctx, notificationText(ctx, input))
        PublicNetwork.post(ctx.params.path("url").asText(),
            json.writeValueAsString(mapOf("runId" to ctx.runId, "coverageStatus" to ctx.coverageStatus, "message" to content)),
            ctx.params.path("token").asText(null))
    }

    @Bean fun smtp(): NodeDefinition = notification(
        "smtp", "Отправить на почту",
        """{"type":"object","properties":{"to":{"type":"string","maxLength":254}},
            "additionalProperties":false}""",
    ) { ctx, input ->
        if (smtpHost.isBlank() || smtpUser.isBlank() || smtpPort !in setOf(25, 587, 2525)) {
            throw NodeFailure("Для уведомления по почте настройте SMTP-сервер, порт и отправителя.")
        }
        val recipient = InternetAddress(ctx.params.path("to").asText(smtpTo), true)
        recipient.validate()
        val properties = Properties().apply {
            setProperty("mail.smtp.starttls.enable", "true")
            setProperty("mail.smtp.starttls.required", "true")
            setProperty("mail.smtp.ssl.checkserveridentity", "true")
            setProperty("mail.smtp.connectiontimeout", "5000")
            setProperty("mail.smtp.timeout", "10000")
            setProperty("mail.smtp.writetimeout", "10000")
            setProperty("mail.smtp.auth", "true")
            setProperty("mail.smtp.socketFactory.fallback", "false")
            put("mail.smtp.socketFactory", PublicNetwork.smtpSockets(smtpHost, smtpPort))
        }
        val session = Session.getInstance(properties)
        val content = deliveryText(ctx, notificationText(ctx, input))
        val message = MimeMessage(session).apply {
            setFrom(InternetAddress(smtpUser, true))
            setRecipient(Message.RecipientType.TO, recipient)
            setSubject("Отчёт проверки ${ctx.runId}", "UTF-8")
            setText(content, "UTF-8")
            saveChanges()
        }
        session.getTransport("smtp").use { transport: Transport ->
            transport.connect(smtpHost, smtpPort, smtpUser, smtpPassword)
            transport.sendMessage(message, message.allRecipients)
        }
    }

    private fun notification(
        type: String,
        title: String,
        params: String,
        secrets: Set<String> = emptySet(),
        send: (NodeContext, NodeInput) -> Unit,
    ): NodeDefinition = PlatformNode("notify.$type", title, NodeCategory.OUTPUT, reportInputs,
        paramsSchema = schema(params), secretParams = secrets, notifyOnFailure = true) { ctx, input ->
        withContext(Dispatchers.IO) { send(ctx, input) }
        NodeOutput(emptyMap())
    }

    private fun deliveryText(ctx: NodeContext, text: String): String = listOf(telegramToken, smtpPassword)
        .filter(String::isNotEmpty).fold(ctx.redact(text)) { safe, secret -> safe.replace(secret, Redaction.MASK) }

    private fun telegramGaps(ctx: NodeContext, input: NodeInput): Sequence<String> =
        if (ctx.coverageStatus == "COMPLETE") emptySequence() else gaps(coverage(ctx, input))

    internal fun telegramMessage(ctx: NodeContext, input: NodeInput, chat: String): Map<String, Any> {
        val options = TelegramCardOptions()
        val text = telegramPriorityCard(ctx, findings(input), telegramGaps(ctx, input), options) { deliveryText(ctx, it) }
        return telegramPayload(ctx, TelegramDestination(chat), text, options, null)
    }

    private fun telegramPayload(
        ctx: NodeContext,
        destination: TelegramDestination,
        text: String,
        options: TelegramCardOptions,
        previousId: String?,
    ): Map<String, Any> = buildMap {
        put("chat_id", destination.chatId)
        put("parse_mode", "HTML")
        put("text", text)
        put("link_preview_options", mapOf("is_disabled" to true))
        destination.threadId?.let { put("message_thread_id", it) }
        if (destination.silent) put("disable_notification", true)
        publicOrigin?.let { origin ->
            val runUrl = "$origin/runs/${ctx.runId}"
            val buttons = if (ctx.failureReason == null) buildList {
                add(listOf(
                    mapOf("text" to options.word("Открыть отчёт", "Open report"), "url" to "$runUrl/report"),
                    mapOf("text" to options.word("Скачать PDF", "Download PDF"),
                        "url" to "$origin/api/runs/${ctx.runId}/report.pdf"),
                ))
                if (previousId != null) add(listOf(
                    mapOf("text" to options.word("Сравнить с предыдущим", "Compare with previous run"),
                        "url" to "$origin/compare?base=$previousId&head=${ctx.runId}"),
                ))
            } else listOf(listOf(mapOf("text" to options.word("Открыть запуск", "Open run"), "url" to runUrl)))
            put("reply_markup", mapOf("inline_keyboard" to buttons))
        }
    }

    private fun telegramReport(
        ctx: NodeContext,
        input: NodeInput,
        safeFindings: List<JsonNode>,
        ai: JsonNode?,
        redact: (String) -> String,
    ): JsonNode {
        val report = json.createObjectNode().put("runId", ctx.runId)
        val selected = if (ai != null) safeFindings else safeFindings.map {
            if (it is ObjectNode && it.has("ai")) it.deepCopy().apply { remove("ai") } else it
        }
        report.set<JsonNode>("findings", json.valueToTree(selected))
        report.set<JsonNode>("coverage", coverage(ctx, input))
        if (ai != null) report.set<JsonNode>("ai", ai)
        return Redaction(json, emptyList()).tree(report, redact)
    }

    /**
     * Готовый файл для формата; null при ошибке или превышении лимита Telegram.
     * Для PDF при сбое — запасной Markdown, если он не выбран отдельно (иначе PDF пропускается без дубля).
     */
    private fun telegramFile(
        ctx: NodeContext,
        report: JsonNode,
        explanation: String?,
        format: TelegramFormat,
        selected: List<TelegramFormat>,
        redact: (String) -> String,
    ): Pair<TelegramFormat, TelegramAttachment?>? {
        if (format == TelegramFormat.PDF) {
            val pdf = runCatching {
                val meta = json.createObjectNode()
                ctx.workflowName?.let { meta.put("workflowName", redact(it)) }
                exporter?.pdf(report, meta)?.takeIf {
                    it.size in 5..MAX_TELEGRAM_ATTACHMENT && String(it, 0, 4, Charsets.ISO_8859_1) == "%PDF"
                }
            }.getOrNull()
            if (pdf != null) {
                return format to TelegramAttachment("report-${ctx.runId.take(8)}.pdf", format.contentType, pdf)
            }
            if (TelegramFormat.MARKDOWN in selected) return null
            return TelegramFormat.MARKDOWN to textAttachment(report, explanation, TelegramFormat.MARKDOWN, redact)
        }
        return format to textAttachment(report, explanation, format, redact)
    }

    private fun textAttachment(
        report: JsonNode,
        explanation: String?,
        format: TelegramFormat,
        redact: (String) -> String,
    ): TelegramAttachment? = runCatching {
        val content = when (format) {
            TelegramFormat.MARKDOWN -> telegramMarkdown(report, explanation)
            TelegramFormat.HTML -> {
                val markdown = telegramHtml(telegramMarkdown(report, explanation))
                "<!doctype html><html><meta charset=\"utf-8\"><title>$PRODUCT_NAME</title><pre>$markdown</pre></html>"
            }
            TelegramFormat.JSON -> json.writeValueAsString(exporter?.json(report) ?: report)
            TelegramFormat.SARIF -> json.writeValueAsString(requireNotNull(exporter?.sarif(report)))
            else -> error("Unsupported attachment format")
        }
        val bytes = redact(content).toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_TELEGRAM_ATTACHMENT) { "Файл превышает лимит Telegram 50 МБ" }
        TelegramAttachment("report.${format.value}", format.contentType, bytes)
    }.getOrNull()

    internal fun telegramMarkdown(ctx: NodeContext, input: NodeInput): String {
        val report = telegramReport(ctx, input, findings(input), null) { deliveryText(ctx, it) }
        return telegramMarkdown(report, explanation(input)?.text?.let { deliveryText(ctx, it) })
    }

    private fun telegramMarkdown(report: JsonNode, explanation: String?): String {
        val coverage = report.path("coverage")
        val status = coverage.path("status").asText()
        val safeFindings = findingsOf(report)
        val markdown = exporter?.markdown(report) ?: buildString {
            appendLine("# Отчёт проверки")
            appendLine()
            appendLine("Покрытие: $status")
            if (status != "COMPLETE") {
                appendLine("Итог проверки неизвестен.")
                gaps(coverage).forEach { appendLine("- $it") }
            }
            if (status == "COMPLETE" || safeFindings.isNotEmpty()) appendLine("Находок: ${safeFindings.size}")
            for (finding in safeFindings) {
                appendLine("- ${finding.path("severity").asText()} · ${finding.path("path").asText()} · ${finding.path("title").asText()}")
            }
        }
        return if (explanation.isNullOrBlank()) markdown else "$markdown\n## Объяснение AI\n\n$explanation\n"
    }

    internal fun notificationText(ctx: NodeContext, input: NodeInput): String {
        val findings = findings(input)
        val content = buildString {
            val failure = ctx.failureReason
            if (failure != null) {
                appendLine("Проверка не выполнена, итог неизвестен.")
                appendLine("Причина: $failure")
            } else {
                appendLine("Покрытие проверки: ${ctx.coverageStatus}")
                if (ctx.coverageStatus != "COMPLETE") appendLine("Анализ не завершён. Итог пока неизвестен.")
                if (ctx.coverageStatus == "COMPLETE" || findings.isNotEmpty()) appendLine("Находок: ${findings.size}")
            }
            if (ctx.coverageStatus != "COMPLETE") {
                gaps(coverage(ctx, input)).forEach { appendLine(it) }
            }
            publicOrigin?.let { appendLine("Запуск: $it/runs/${ctx.runId}") }
            if (failure == null) {
                for (finding in findings.take(30)) {
                    appendLine("${finding.path("severity").asText()} · ${finding.path("path").asText()} · ${finding.path("title").asText()}")
                }
                explanation(input)?.let { appendLine(it.text) }
            }
        }
        return ctx.redact(content)
    }

    private fun coverage(ctx: NodeContext, input: NodeInput): JsonNode {
        val incoming = json.valueToTree<JsonNode>(input.ports["report"])?.path("coverage")
        val analyzers = if (ctx.coverageByAnalyzer.isEmpty()) incoming?.path("byAnalyzer") else {
            json.valueToTree(ctx.coverageByAnalyzer)
        }
        return json.createObjectNode().put("status", ctx.coverageStatus).apply {
            if (analyzers?.isObject == true) set<JsonNode>("byAnalyzer", analyzers)
        }
    }

    private fun gaps(coverage: JsonNode): Sequence<String> = coverage.path("byAnalyzer").asSequence().flatMap { analyzer ->
        sequenceOf("filesSkipped", "unresolved").flatMap { analyzer.path(it).asSequence() }
    }.mapNotNull { entry ->
        val reason = entry.path("reason").textValue()?.trim()?.takeIf(String::isNotEmpty) ?: return@mapNotNull null
        val path = entry.path("path").textValue()?.trim()?.takeIf(String::isNotEmpty) ?: "Путь неизвестен"
        val location = entry.path("line").asInt().takeIf { it > 0 }?.let { "$path:$it" } ?: path
        "${location.replace(spaces, " ").take(180)} - ${reason.replace(spaces, " ").take(260)}"
    }.distinct().take(5)

    private fun findings(input: NodeInput): List<JsonNode> =
        listOfNotNull(input.ports["findings"], input.ports["report"])
            .flatMap { findingsOf(json.valueToTree(it)) }
            .distinctBy { it.path("fingerprint").asText().ifEmpty { it.toString() } }

    private fun explanation(input: NodeInput): ValidatedExplanation? {
        val direct = input.ports["explanation"] as? ValidatedExplanation
        val report = input.ports["report"] as? Map<*, *>
        return direct ?: report?.get("explanation") as? ValidatedExplanation
    }

    private data class ReportExplanation(override val text: String) : ValidatedExplanation
}
