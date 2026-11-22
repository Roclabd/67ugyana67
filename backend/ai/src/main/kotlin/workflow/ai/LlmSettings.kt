package workflow.ai

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import ru.codeguard.ai.llm.ChatMessage
import ru.codeguard.ai.llm.LlmClient
import ru.codeguard.ai.llm.LlmConfig
import ru.codeguard.ai.llm.LlmReply
import ru.codeguard.ai.llm.OpenAiCompatibleClient
import java.net.URI
import java.util.concurrent.atomic.AtomicReference

/**
 * Текущий провайдер LLM. При старте — из LLM_* (.env), дальше меняется экраном «Настройки LLM».
 * Изменение живёт до перезапуска сервера: постоянная настройка — .env, ключ на диск не пишется.
 */
class LlmRuntime(initial: LlmConfig?) {
    private data class Current(val config: LlmConfig, val provider: String, val client: LlmClient)

    private val current = AtomicReference(initial?.let { Current(it, it.provider, OpenAiCompatibleClient(it)) })

    fun client(): LlmClient? = current.get()?.client

    /** Адрес из .env может нести учётные данные (логин, подписанный query): такие значения не отдаём. */
    fun settings(): LlmSettingsView = current.get()?.let {
        val key = it.config.apiKey?.takeIf(String::isNotBlank)
        fun safe(value: String) = if (key != null && key in value) "" else value
        val uri = runCatching { URI(it.config.baseUrl) }.getOrNull()
        val baseUrl = if (uri?.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) it.config.baseUrl else ""
        LlmSettingsView(it.provider, safe(baseUrl), safe(it.config.model), key != null)
    } ?: LlmSettingsView("openai-compatible", "", "", false)

    /** Ключ сохраняется, только если адрес остался тем же сервером: иначе сменой адреса можно было бы увести ключ. */
    fun update(request: LlmSettingsUpdate): LlmSettingsView {
        val (provider, baseUrl, model, apiKey) = LlmSettingsRules.check(request)
        current.updateAndGet { previous ->
            val keptKey = previous?.config?.apiKey?.takeIf { LlmSettingsRules.sameServer(previous.config.baseUrl, baseUrl) }
            val base = previous?.config ?: LlmConfig(baseUrl, model, proxy = System.getenv("APP_OUTBOUND_PROXY")?.takeIf { it.isNotBlank() })
            val config = base.copy(baseUrl = baseUrl, model = model, apiKey = apiKey ?: keptKey)
            Current(config, provider, OpenAiCompatibleClient(config))
        }
        return settings()
    }

    /** Клиент для генератора сценариев: каждый запрос идёт к провайдеру, выбранному сейчас. */
    fun switchable(): LlmClient = object : LlmClient {
        override val config: LlmConfig get() = requireNotNull(current.get()) { "LLM не настроена" }.config
        override fun chat(messages: List<ChatMessage>): LlmReply =
            requireNotNull(current.get()) { "LLM не настроена" }.client.chat(messages)
    }
}

data class LlmSettingsView(val provider: String, val baseUrl: String, val model: String, val apiKeySet: Boolean)

data class LlmSettingsUpdate(val provider: String? = null, val baseUrl: String? = null, val model: String? = null, val apiKey: String? = null)

class InvalidLlmSettings(message: String) : RuntimeException(message)

internal object LlmSettingsRules {
    val providers = setOf("openai-compatible", "groq", "openrouter", "ollama", "vllm")
    private val modelName = Regex("[A-Za-z0-9._:/@+-]{1,200}")
    private val loopback = setOf("localhost", "127.0.0.1", "[::1]", "::1")

    data class Checked(val provider: String, val baseUrl: String, val model: String, val apiKey: String?)

    fun check(request: LlmSettingsUpdate): Checked {
        val provider = request.provider?.takeIf { it in providers }
            ?: throw InvalidLlmSettings("Выберите провайдера: ${providers.joinToString()}")
        val baseUrl = request.baseUrl?.trim()?.trimEnd('/').orEmpty()
        val uri = runCatching { URI(baseUrl) }.getOrNull()
        val host = uri?.host?.lowercase()
        if (baseUrl.length > 300 || uri == null || host == null || uri.userInfo != null || uri.query != null || uri.fragment != null ||
            !(uri.scheme == "https" || uri.scheme == "http" && host in loopback)
        ) throw InvalidLlmSettings("Base URL: https://… или http://localhost:порт/… для локальной модели")
        val model = request.model?.trim().orEmpty()
        if (!modelName.matches(model)) throw InvalidLlmSettings("Укажите модель: латиница, цифры и . _ : / @ + -, до 200 символов")
        val apiKey = request.apiKey?.takeIf { it.isNotBlank() }
        if (apiKey != null && (apiKey.length > 500 || apiKey.any { it.isWhitespace() || it.isISOControl() })) {
            throw InvalidLlmSettings("Ключ API: до 500 символов, без пробелов и переводов строки")
        }
        return Checked(provider, baseUrl, model, apiKey)
    }

    fun sameServer(a: String, b: String): Boolean {
        val x = URI(a)
        val y = URI(b)
        fun port(u: URI) = if (u.port != -1) u.port else if (u.scheme == "https") 443 else 80
        return x.scheme == y.scheme && x.host.equals(y.host, ignoreCase = true) && port(x) == port(y)
    }
}

@RestController
@RequestMapping("/api/settings/llm")
class LlmSettingsController(private val runtime: LlmRuntime) {
    @GetMapping
    fun get(): LlmSettingsView = runtime.settings()

    @PutMapping
    fun put(@RequestBody request: LlmSettingsUpdate): ResponseEntity<Any> = try {
        ResponseEntity.ok(runtime.update(request))
    } catch (error: InvalidLlmSettings) {
        ResponseEntity.status(422).body(mapOf("code" to "INVALID_INPUT", "message" to error.message))
    }
}
