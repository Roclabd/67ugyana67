package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull
import org.springframework.stereotype.Component
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock

const val TELEGRAM_CHAT_LIST_MAX_LENGTH = 4096
private const val TELEGRAM_MAX_PARALLEL_REQUESTS = 8
private const val TELEGRAM_DELIVERY_BUDGET_MS = 30_000L
internal const val TELEGRAM_RETRY_BUDGET_MS = 15_000L
private val telegramRequestInterval = TimeUnit.MILLISECONDS.toNanos(50)
private val telegramSlots = Semaphore(TELEGRAM_MAX_PARALLEL_REQUESTS)

enum class TelegramFormat(val value: String, val contentType: String) {
    PDF("pdf", "application/pdf"),
    MARKDOWN("md", "text/markdown"),
    HTML("html", "text/html"),
    JSON("json", "application/json"),
    SARIF("sarif", "application/sarif+json"),
    NONE("none", "");

    companion object {
        fun parse(value: String?): TelegramFormat? = entries.firstOrNull { it.value == value }

        /** Допустимые вложения в порядке отправки (без «none»). */
        val attachable: List<TelegramFormat> = listOf(PDF, MARKDOWN, HTML, JSON, SARIF)

        /** Список из значений; null при неизвестном значении. Дубликаты убираются, порядок канонический. */
        fun parseList(values: Iterable<String?>): List<TelegramFormat>? {
            val parsed = values.map { parse(it)?.takeIf { f -> f != NONE } ?: return null }
            return attachable.filter { it in parsed }
        }

        /**
         * Вложения из параметров: новый массив `attachments`, иначе устаревший одиночный `format`
         * (none -> пусто). Null, если ничего не задано или значение некорректно.
         */
        fun fromParams(params: JsonNode): List<TelegramFormat>? {
            val list = params.path("attachments")
            if (list.isArray) return parseList(list.map { it.textValue() })
            val legacy = params.path("format").textValue() ?: return null
            if (legacy == NONE.value) return emptyList()
            return parseList(listOf(legacy))
        }
    }
}

class TelegramDefaults(val token: String, val chatId: String, val attachments: List<TelegramFormat>)

fun interface TelegramDefaultsSource {
    fun defaults(): TelegramDefaults
}

data class TelegramPreviousRun(val runId: String, val added: List<JsonNode>)

fun interface TelegramRunHistory {
    fun previous(runId: String, current: List<JsonNode>?): TelegramPreviousRun?
}

data class TelegramDestination(val chatId: String, val threadId: Int? = null, val silent: Boolean = false)

data class TelegramAttachment(val filename: String, val contentType: String, val content: ByteArray)

interface TelegramTransport {
    fun message(token: String, body: String)
    fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment)

    /** Long polling `getUpdates`: сырой JSON-ответ Telegram. 409 приходит как [DeliveryHttpFailure]. */
    fun updates(token: String, offset: Long, timeoutSeconds: Int): String =
        throw UnsupportedOperationException("getUpdates не поддерживается этим транспортом")
}

class DeliveryHttpFailure(val status: Int, val retryAfterSeconds: Int? = null) : RuntimeException("Delivery failed (HTTP $status)")

@Component
class TelegramHttpTransport : TelegramTransport {
    private val sendClock = ReentrantLock(true)
    private var nextRequest = System.nanoTime()

    override fun message(token: String, body: String) = send {
        PublicNetwork.post(endpoint(token, "sendMessage"), body)
    }

    override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) = send {
        PublicNetwork.sendTelegramDocument(endpoint(token, "sendDocument"), destination, attachment)
    }

    override fun updates(token: String, offset: Long, timeoutSeconds: Int): String {
        var body = ""
        send {
            body = PublicNetwork.postForBody(endpoint(token, "getUpdates"),
                """{"offset":$offset,"timeout":$timeoutSeconds,"allowed_updates":["message"]}""", timeoutSeconds + 10L)
        }
        return body
    }

    private fun send(request: () -> Unit) {
        sendClock.lockInterruptibly()
        try {
            val wait = nextRequest - System.nanoTime()
            if (wait > 0) TimeUnit.NANOSECONDS.sleep(wait)
            nextRequest = System.nanoTime() + telegramRequestInterval
        } finally {
            sendClock.unlock()
        }
        request()
    }

    private fun endpoint(token: String, method: String): String {
        require(validTelegramToken(token)) { "Invalid Telegram token" }
        return "https://api.telegram.org/bot$token/$method"
    }
}

data class TelegramBatchResult<T>(val sent: List<T>, val failure: Exception?)

suspend fun <T : Any> sendTelegramBatch(recipients: List<T>, retryBudget: AtomicLong = AtomicLong(TELEGRAM_RETRY_BUDGET_MS), send: (T) -> Unit): TelegramBatchResult<T> {
    val sent = ConcurrentLinkedQueue<T>()
    val next = AtomicInteger()
    val firstFailure = AtomicReference<Exception?>()
    withTimeoutOrNull(TELEGRAM_DELIVERY_BUDGET_MS) {
        repeat(minOf(TELEGRAM_MAX_PARALLEL_REQUESTS, recipients.size)) {
            launch {
                while (isActive) {
                    val recipient = recipients.getOrNull(next.getAndIncrement()) ?: break
                    try {
                        telegramRetry(retryBudget) {
                            telegramSlots.withPermit { runInterruptible(Dispatchers.IO) { send(recipient) } }
                        }
                        sent.add(recipient)
                    } catch (failure: CancellationException) {
                        throw failure
                    } catch (failure: Exception) {
                        firstFailure.compareAndSet(null, failure)
                    }
                }
            }
        }
    }
    return TelegramBatchResult(sent.toList(), firstFailure.get())
}

private val botToken = Regex("[0-9]{1,25}:[A-Za-z0-9_-]{15,120}")
private val chatAddress = Regex("(?:-?[0-9]{1,19}|@[A-Za-z0-9_]{1,32})")

fun validTelegramToken(token: String): Boolean = botToken.matches(token)

fun telegramChats(value: String): List<String>? {
    if (value.length > TELEGRAM_CHAT_LIST_MAX_LENGTH) return null
    val chats = value.split(',').map(String::trim)
    if (chats.any { !chatAddress.matches(it) }) return null
    return chats.distinct()
}

internal fun telegramHtml(value: String): String =
    value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

/** До двух повторов при 429: пауза retry_after, не дольше 5 с, в пределах общего бюджета запуска; иначе отказ. */
private suspend fun <T> telegramRetry(budget: AtomicLong, call: suspend () -> T): T {
    var attempt = 0
    while (true) {
        try {
            return call()
        } catch (failure: DeliveryHttpFailure) {
            if (failure.status != 429 || attempt >= 2) throw failure
            val wait = ((failure.retryAfterSeconds ?: 1).coerceAtLeast(0) * 1000L).coerceAtMost(5000L)
            if (budget.addAndGet(-wait) < 0) throw failure
            attempt++
            delay(wait)
        }
    }
}
