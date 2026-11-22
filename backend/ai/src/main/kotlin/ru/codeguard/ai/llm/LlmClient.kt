package ru.codeguard.ai.llm

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Настройки LLM. Переключение «облако ↔ локальная модель» — только сменой этих значений, без изменения кода:
 *   Groq:       LLM_BASE_URL=https://api.groq.com/openai/v1      LLM_MODEL=llama-3.3-70b-versatile  LLM_API_KEY=…
 *   OpenRouter: LLM_BASE_URL=https://openrouter.ai/api/v1         LLM_MODEL=…:free                    LLM_API_KEY=…
 *   Ollama:     LLM_BASE_URL=http://localhost:11434/v1             LLM_MODEL=qwen2.5-coder:7b          (ключ не нужен)
 *   vLLM:       LLM_BASE_URL=http://localhost:8000/v1              LLM_MODEL=<имя модели>
 */
data class LlmConfig(
    val baseUrl: String,
    val model: String,
    val apiKey: String? = null,
    val timeout: Duration = Duration.ofSeconds(90),
    /** Сколько раз переспросить модель, если ответ не прошёл проверку схемы. */
    val maxAttempts: Int = 3,
    /** Просить у сервера JSON-режим (response_format). Некоторые локальные серверы его не поддерживают. */
    val jsonMode: Boolean = true,
    val temperature: Double = 0.0,
    /** Исходящий HTTP-прокси (APP_OUTBOUND_PROXY, http://host:port); пусто - напрямую. Локальные серверы идут мимо него. */
    val proxy: String? = null,
) {
    /** Имя провайдера для отчёта — по адресу, без ключа. */
    val provider: String
        get() = when {
            "groq" in baseUrl -> "groq"
            "openrouter" in baseUrl -> "openrouter"
            ":11434" in baseUrl || "ollama" in baseUrl -> "ollama"
            ":8000" in baseUrl || "vllm" in baseUrl -> "vllm"
            "openai.com" in baseUrl -> "openai"
            else -> "openai-compatible"
        }

    override fun toString() = "LlmConfig(provider=$provider, baseUrl=$baseUrl, model=$model, apiKey=${if (apiKey.isNullOrBlank()) "—" else "задан"})"

    companion object {
        /**
         * Переменные из файла .env (KEY=value, # — комментарии). Значения не печатаются.
         * Переменные окружения процесса важнее файла.
         */
        fun loadDotEnv(path: java.nio.file.Path): Map<String, String> {
            if (!java.nio.file.Files.exists(path)) return emptyMap()
            return java.nio.file.Files.readAllLines(path).mapNotNull { raw ->
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#") || '=' !in line) return@mapNotNull null
                val key = line.substringBefore('=').trim().removePrefix("export ").trim()
                val value = line.substringAfter('=').trim().removeSurrounding("\"").removeSurrounding("'")
                key to value
            }.toMap()
        }

        /** Из переменных окружения; null — LLM не настроена (это не ошибка: отчёт уйдёт без объяснений, с явной пометкой). */
        fun fromEnv(env: Map<String, String> = System.getenv()): LlmConfig? {
            val url = env["LLM_BASE_URL"]?.takeIf { it.isNotBlank() } ?: return null
            val model = env["LLM_MODEL"]?.takeIf { it.isNotBlank() } ?: return null
            return LlmConfig(
                baseUrl = url.trimEnd('/'),
                model = model,
                apiKey = env["LLM_API_KEY"]?.takeIf { it.isNotBlank() },
                timeout = Duration.ofSeconds(env["LLM_TIMEOUT_SECONDS"]?.toLongOrNull() ?: 90),
                maxAttempts = env["LLM_MAX_ATTEMPTS"]?.toIntOrNull()?.coerceIn(1, 5) ?: 3,
                jsonMode = env["LLM_JSON_MODE"]?.lowercase() != "false",
                proxy = env["APP_OUTBOUND_PROXY"]?.takeIf { it.isNotBlank() },
            )
        }
    }
}

data class ChatMessage(val role: String, val content: String)

data class LlmReply(val content: String, val promptTokens: Int?, val completionTokens: Int?)

/** Ошибка обращения к модели: сеть, таймаут, HTTP-ошибка. Сообщение без ключа и без содержимого запроса. */
class LlmUnavailableException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Клиент чат-модели. Реализация — [OpenAiCompatibleClient]; в тестах — подставной клиент со сценарием ответов. */
interface LlmClient {
    val config: LlmConfig
    fun chat(messages: List<ChatMessage>): LlmReply
}

/** POST {baseUrl}/chat/completions — протокол OpenAI, который понимают Groq, OpenRouter, Ollama и vLLM. */
class OpenAiCompatibleClient(override val config: LlmConfig, private val http: HttpClient = defaultHttp(config)) : LlmClient {
    private val json: ObjectMapper = jacksonObjectMapper()

    override fun chat(messages: List<ChatMessage>): LlmReply {
        val body = buildMap<String, Any> {
            put("model", config.model)
            put("temperature", config.temperature)
            put("messages", messages.map { mapOf("role" to it.role, "content" to it.content) })
            if (config.jsonMode) put("response_format", mapOf("type" to "json_object"))
        }
        val request = HttpRequest.newBuilder(URI.create(config.baseUrl + "/chat/completions"))
            .timeout(config.timeout)
            .header("Content-Type", "application/json")
            .apply { config.apiKey?.let { header("Authorization", "Bearer $it") } }
            .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)))
            .build()
        var response = send(request)
        // Бесплатные тарифы (Groq, OpenRouter) ограничивают запросы в минуту: 429 — подождать и повторить, не считая ошибкой.
        var rateLimitRetries = 0
        var waited = 0.0
        while (response.statusCode() == 429 && rateLimitRetries < 4 && waited < MAX_RATE_LIMIT_WAIT_SECONDS) {
            val wait = (response.headers().firstValue("retry-after").map { it.toDoubleOrNull() }.orElse(null)?.coerceIn(1.0, 60.0) ?: (5.0 * (rateLimitRetries + 1)))
                .coerceAtMost(MAX_RATE_LIMIT_WAIT_SECONDS - waited)
            waited += wait
            Thread.sleep((wait * 1000).toLong())
            rateLimitRetries++
            response = send(request)
        }
        if (response.statusCode() !in 200..299) {
            // Тело ответа провайдера в сообщение не берём: оно может эхом содержать фрагменты запроса (в т. ч. секреты) —
            // наружу только код и безопасная классификация.
            throw LlmUnavailableException("Сервер модели вернул HTTP ${response.statusCode()} (${httpClassification(response.statusCode())})")
        }
        val root = try {
            json.readTree(response.body())
        } catch (e: Exception) {
            throw LlmUnavailableException("Сервер модели вернул не JSON", e)
        }
        val content = root.path("choices").path(0).path("message").path("content").asText(null)
            ?: throw LlmUnavailableException("В ответе сервера нет choices[0].message.content")
        val usage = root.path("usage")
        return LlmReply(content, usage.path("prompt_tokens").takeIf { it.isNumber }?.asInt(), usage.path("completion_tokens").takeIf { it.isNumber }?.asInt())
    }

    private fun httpClassification(code: Int) = when (code) {
        400 -> "запрос отклонён провайдером"
        401, 403 -> "неверный ключ или нет доступа (в т. ч. по региону)"
        404 -> "неверный адрес или модель"
        413 -> "слишком большой запрос"
        429 -> "превышен лимит запросов"
        in 500..599 -> "ошибка на стороне провайдера"
        else -> "неожиданный ответ"
    }

    private fun send(request: HttpRequest): HttpResponse<String> = try {
        http.send(request, HttpResponse.BodyHandlers.ofString())
    } catch (e: java.net.http.HttpTimeoutException) {
        throw LlmUnavailableException("Модель не ответила за ${config.timeout.seconds} с", e)
    } catch (e: java.io.IOException) {
        throw LlmUnavailableException("Сервер модели недоступен: ${e.javaClass.simpleName}", e)
    }

    companion object {
        /** Общий потолок ожидания из-за лимита запросов на один вызов — чтобы задание не зависало. */
        const val MAX_RATE_LIMIT_WAIT_SECONDS = 90.0

        fun defaultHttp(config: LlmConfig): HttpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .apply { proxySelector(config)?.let { proxy(it) } }
            .build()

        /** Прокси для внешних провайдеров; локальный сервер модели (localhost, 127.0.0.1, ::1) всегда напрямую. */
        fun proxySelector(config: LlmConfig): java.net.ProxySelector? {
            val uri = runCatching { URI.create(config.proxy?.trim().orEmpty()) }.getOrNull() ?: return null
            if (uri.scheme != "http" || uri.host.isNullOrEmpty() || uri.port !in 1..65535) return null
            val target = runCatching { URI.create(config.baseUrl).host }.getOrNull()?.removePrefix("[")?.removeSuffix("]")?.lowercase()
            if (target == null || target == "localhost" || target.endsWith(".localhost") || target == "127.0.0.1" || target == "::1") return null
            return java.net.ProxySelector.of(java.net.InetSocketAddress(uri.host, uri.port))
        }
    }
}
