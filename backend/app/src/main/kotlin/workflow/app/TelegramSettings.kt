package workflow.app

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.runBlocking
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import workflow.engine.Redaction
import workflow.nodes.DeliveryHttpFailure
import workflow.nodes.InputRejected
import workflow.nodes.TelegramDefaults
import workflow.nodes.TelegramDefaultsSource
import workflow.nodes.TelegramFormat
import workflow.nodes.TelegramTransport
import workflow.nodes.sendTelegramBatch
import workflow.nodes.telegramChats
import workflow.nodes.validTelegramToken

private const val TELEGRAM_SECRET_OWNER = "integrations/telegram/token"

data class TelegramSettingsView(
    val token: String,
    val tokenSaved: Boolean,
    val chatId: String,
    val attachments: List<String>,
    /** Устаревшее поле для старых клиентов: первое вложение или none. */
    val format: String,
)
data class TelegramSettingsUpdate(
    val token: String? = null,
    val chatId: String? = null,
    val attachments: List<String>? = null,
    val format: String? = null,
)
data class TelegramTestRequest(val token: String? = null, val chatId: String? = null, val language: String? = null)

@Service
class TelegramSettingsStore(
    private val db: JdbcTemplate,
    private val json: ObjectMapper,
    private val secrets: SecretBox,
    @Value("\${TELEGRAM_BOT_TOKEN:}") private val envToken: String,
    @Value("\${TELEGRAM_CHAT_ID:}") private val envChatId: String,
) : TelegramDefaultsSource {
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    private data class Stored(
        val sealedToken: String? = null,
        val chatId: String = "",
        val attachments: List<String>? = null,
        /** Старое одиночное значение; читается, если списка ещё нет. */
        val format: String? = null,
    ) {
        fun formats(): List<TelegramFormat> = when {
            attachments != null -> TelegramFormat.parseList(attachments) ?: listOf(TelegramFormat.PDF)
            format == TelegramFormat.NONE.value -> emptyList()
            else -> TelegramFormat.parseList(listOf(format ?: "pdf")) ?: listOf(TelegramFormat.PDF)
        }
    }

    private fun read(): Stored =
        db.query("SELECT payload FROM telegram_settings WHERE id = 1") { row, _ ->
            json.readValue(row.getString(1), Stored::class.java)
        }.singleOrNull() ?: Stored()

    private fun view(stored: Stored) = TelegramSettingsView(
        token = if (stored.sealedToken != null || envToken.isNotBlank()) Redaction.MASK else "",
        tokenSaved = stored.sealedToken != null,
        chatId = stored.chatId.ifBlank { envChatId },
        attachments = stored.formats().map { it.value },
        format = stored.formats().firstOrNull()?.value ?: TelegramFormat.NONE.value,
    )

    fun view(): TelegramSettingsView = view(read())

    override fun defaults(): TelegramDefaults {
        val stored = read()
        return TelegramDefaults(
            token = stored.sealedToken?.let { secrets.open(it, TELEGRAM_SECRET_OWNER) } ?: envToken,
            chatId = stored.chatId.ifBlank { envChatId },
            attachments = stored.formats(),
        )
    }

    @Synchronized
    fun save(update: TelegramSettingsUpdate): TelegramSettingsView {
        val old = read()
        val reject = InputRejected("Выберите поддерживаемые форматы вложений")
        val attachments = when {
            update.attachments != null -> {
                if (update.attachments.size > 5 || update.attachments.distinct().size != update.attachments.size) throw reject
                (TelegramFormat.parseList(update.attachments) ?: throw reject).map { it.value }
            }
            update.format == TelegramFormat.NONE.value -> emptyList()
            update.format != null -> listOf((TelegramFormat.parseList(listOf(update.format)) ?: throw reject).single().value)
            else -> old.formats().map { it.value }
        }
        val chatId = update.chatId?.trim()?.also {
            if (it.isNotEmpty() && telegramChats(it) == null) {
                throw InputRejected("Укажите корректные ID или @имена чатов через запятую")
            }
        } ?: old.chatId
        val sealedToken = when (val token = update.token?.trim()) {
            null, Redaction.MASK -> old.sealedToken
            "" -> null
            else -> {
                if (!validTelegramToken(token)) throw InputRejected("Проверьте формат токена Telegram")
                secrets.seal(token, TELEGRAM_SECRET_OWNER)
            }
        }

        val stored = Stored(sealedToken, chatId, attachments)
        db.update("MERGE INTO telegram_settings (id, payload) KEY(id) VALUES (1, ?)", json.writeValueAsString(stored))
        return view(stored)
    }

    fun testCredentials(request: TelegramTestRequest): Pair<String, String> {
        val stored = read()
        val token = when (val entered = request.token?.trim()) {
            null, Redaction.MASK -> stored.sealedToken?.let { secrets.open(it, TELEGRAM_SECRET_OWNER) } ?: envToken
            "" -> envToken
            else -> entered
        }
        return token to (request.chatId ?: stored.chatId).ifBlank { envChatId }
    }
}

@RestController
@RequestMapping("/api/integrations/telegram")
class TelegramSettingsController(
    private val settings: TelegramSettingsStore,
    private val transport: TelegramTransport,
    private val json: ObjectMapper,
    private val demo: DemoMode,
) {
    @GetMapping
    fun get() = settings.view().let { if (demo.enabled) it.copy(chatId = "") else it }

    @PutMapping(consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun put(@RequestBody update: TelegramSettingsUpdate) = settings.save(update)

    @PostMapping("/test", consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun test(@RequestBody request: TelegramTestRequest): ResponseEntity<Map<String, String>> {
        val (token, chatId) = settings.testCredentials(request)
        if (!validTelegramToken(token)) return error(401, "TELEGRAM_TOKEN", "Проверьте токен Telegram-бота.")
        val chats = telegramChats(chatId)
            ?: return error(400, "TELEGRAM_CHAT", "Укажите ID чата Telegram.")
        val text = if (request.language == "en") "$PRODUCT_NAME: Telegram connection confirmed."
            else "$PRODUCT_NAME: подключение Telegram работает."
        val result = runBlocking {
            sendTelegramBatch(chats) { chat ->
                transport.message(token, json.writeValueAsString(mapOf("chat_id" to chat, "text" to text)))
            }
        }
        if (result.sent.size == chats.size) return ResponseEntity.ok(mapOf("status" to "sent"))
        if (result.sent.isNotEmpty()) {
            return error(502, "TELEGRAM_PARTIAL", "Тестовое сообщение доставлено только в часть чатов.")
        }
        return when ((result.failure as? DeliveryHttpFailure)?.status) {
            401, 404 -> error(401, "TELEGRAM_TOKEN", "Проверьте токен Telegram-бота.")
            400 -> error(400, "TELEGRAM_CHAT", "Telegram не нашёл чат. Проверьте ID и добавьте бота в чат.")
            403 -> error(403, "TELEGRAM_FORBIDDEN", "У бота нет доступа к чату Telegram.")
            429 -> error(429, "TELEGRAM_RATE_LIMIT", "Telegram ограничил частоту отправки. Повторите проверку позже.")
            else -> if (result.failure == null) error(504, "TELEGRAM_TIMEOUT", "Истекло время отправки тестового сообщения.")
                else networkError()
        }
    }

    private fun networkError() =
        error(502, "TELEGRAM_NETWORK", "Не удалось безопасно подключиться к Telegram. Проверьте сеть и прокси.")
}
