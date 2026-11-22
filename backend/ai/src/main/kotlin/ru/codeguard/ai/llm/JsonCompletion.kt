package ru.codeguard.ai.llm

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/** Итог проверки ответа модели: значение или список ошибок для повторного запроса. */
sealed interface Checked<out T> {
    data class Ok<T>(val value: T) : Checked<T>
    data class Invalid(val errors: List<String>) : Checked<Nothing>
}

data class JsonOutcome<T>(
    val value: T?,
    val attempts: Int,
    val schemaFailures: Int,
    val fromCache: Boolean,
    /** Почему значения нет: модель недоступна или все попытки не прошли проверку. */
    val error: String?,
    /** Модель недоступна (сеть, таймаут, HTTP-ошибка) — в отличие от «ответила, но не по схеме». */
    val unavailable: Boolean = false,
)

/** Структурный журнал обращений к модели: одна JSON-строка на событие, без кода, промптов и секретов. */
fun interface AiLog {
    fun event(name: String, fields: Map<String, Any?>)

    companion object {
        private val json = jacksonObjectMapper()
        val STDERR = AiLog { name, fields -> System.err.println(json.writeValueAsString(mapOf("event" to name) + fields)) }
        val NONE = AiLog { _, _ -> }
    }
}

/** Кэш проверенных ответов по хэшу запроса: экономит лимиты бесплатных API и делает демо воспроизводимым. */
interface ResponseCache {
    fun get(key: String): String?
    fun put(key: String, value: String)
}

/** Файловый кэш. Работает «как получится»: сбой чтения/записи не мешает вернуть результат. Запись атомарная. */
class FileResponseCache(private val dir: Path) : ResponseCache {
    override fun get(key: String): String? = runCatching { dir.resolve("$key.json").takeIf { Files.exists(it) }?.let { Files.readString(it) } }.getOrNull()
    override fun put(key: String, value: String) {
        runCatching {
            Files.createDirectories(dir)
            val tmp = Files.createTempFile(dir, key, ".tmp")
            Files.writeString(tmp, value)
            Files.move(tmp, dir.resolve("$key.json"), java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        }
    }
}

class MemoryResponseCache : ResponseCache {
    private val map = mutableMapOf<String, String>()
    override fun get(key: String) = map[key]
    override fun put(key: String, value: String) { map[key] = value }
}

/**
 * Запрос JSON у модели с проверкой: ответ → разбор (с починкой типичных огрехов) → проверка [validate] →
 * при ошибке повторный запрос с текстом ошибки, не больше config.maxAttempts. В кэш попадают только прошедшие проверку ответы.
 * Используется для объяснения находок и (B7) для генерации сценария из текста.
 */
class JsonCompletion(
    private val client: LlmClient,
    private val cache: ResponseCache? = null,
    private val log: AiLog = AiLog.NONE,
) {
    private val json: ObjectMapper = jacksonObjectMapper()

    fun <T> complete(task: String, promptVersion: String, messages: List<ChatMessage>, validate: (JsonNode) -> Checked<T>): JsonOutcome<T> {
        val key = cacheKey(promptVersion, messages)
        runCatching { cache?.get(key) }.getOrNull()?.let { cached ->
            val node = parseLenient(cached)
            if (node != null) {
                val checked = validate(node)
                if (checked is Checked.Ok) {
                    log.event("llm.cache_hit", mapOf("task" to task, "model" to client.config.model))
                    return JsonOutcome(checked.value, 0, 0, true, null)
                }
            }
        }
        val conversation = messages.toMutableList()
        var failures = 0
        var lastErrors: List<String> = emptyList()
        for (attempt in 1..client.config.maxAttempts) {
            val started = System.nanoTime()
            val reply = try {
                client.chat(conversation)
            } catch (e: LlmUnavailableException) {
                log.event("llm.unavailable", mapOf("task" to task, "provider" to client.config.provider, "model" to client.config.model, "attempt" to attempt, "error" to e.message))
                return JsonOutcome(null, attempt, failures, false, e.message, unavailable = true)
            }
            val ms = (System.nanoTime() - started) / 1_000_000
            val node = if (reply.content.length > MAX_REPLY_CHARS) null else parseLenient(reply.content)
            val checked: Checked<T> = when {
                reply.content.length > MAX_REPLY_CHARS -> Checked.Invalid(listOf("Ответ слишком большой (${reply.content.length} символов), сократи объяснения"))
                node == null -> Checked.Invalid(listOf("Ответ не является JSON-объектом"))
                else -> runCatching { validate(node) }.getOrElse { Checked.Invalid(listOf("Ответ не прошёл проверку: ${it.javaClass.simpleName}")) }
            }
            log.event(
                "llm.call",
                mapOf(
                    "task" to task, "provider" to client.config.provider, "model" to client.config.model, "attempt" to attempt,
                    "durationMs" to ms, "promptTokens" to reply.promptTokens, "completionTokens" to reply.completionTokens,
                    "valid" to (checked is Checked.Ok), "errors" to (checked as? Checked.Invalid)?.errors?.take(5),
                ),
            )
            when (checked) {
                is Checked.Ok -> {
                    // в кэш - только проверенный разобранный ответ, где секретоподобные строки замаскированы
                    runCatching { cache?.put(key, ru.codeguard.ai.context.CodeContext.scrubText(json.writeValueAsString(node))) }
                    return JsonOutcome(checked.value, attempt, failures, false, null)
                }
                is Checked.Invalid -> {
                    failures++
                    lastErrors = checked.errors
                    conversation += ChatMessage("assistant", reply.content.take(8000))
                    conversation += ChatMessage(
                        "user",
                        "Ответ не прошёл проверку:\n- " + checked.errors.take(10).joinToString("\n- ") +
                            "\nВерни ТОЛЬКО исправленный JSON-объект по той же схеме, без пояснений и без markdown.",
                    )
                }
            }
        }
        return JsonOutcome(null, client.config.maxAttempts, failures, false, "Ответ модели не прошёл проверку схемы: ${lastErrors.take(3).joinToString("; ")}")
    }

    private fun cacheKey(promptVersion: String, messages: List<ChatMessage>): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("${client.config.baseUrl}|${client.config.model}|$promptVersion|".toByteArray())
        md.update(json.writeValueAsBytes(messages))
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    companion object {
        private val mapper = jacksonObjectMapper()

        /**
         * Разбор с починкой типичных огрехов моделей (аналог json_repair): ограждения ```json, текст до/после объекта,
         * висячие запятые. Если и после этого не JSON-объект — null.
         */
        const val MAX_REPLY_CHARS = 200_000

        fun parseLenient(raw: String): JsonNode? {
            var s = raw.trim().removePrefix("﻿")
            // Сначала строгий JSON: ``` внутри строковых полей (fixExample) не должны ломать разбор.
            runCatching { mapper.readTree(s) }.getOrNull()?.takeIf { it.isObject }?.let { return it }
            // Обёртку ```json … ``` снимаем, только если она охватывает весь ответ.
            Regex("^```(?:json)?\\s*([\\s\\S]*?)\\s*```$").find(s)?.let { s = it.groupValues[1].trim() }
            val start = s.indexOf('{')
            val end = s.lastIndexOf('}')
            if (start < 0 || end <= start) return null
            s = s.substring(start, end + 1)
            val attempts = listOf(s, s.replace(Regex(",\\s*([}\\]])"), "$1"))
            for (candidate in attempts) {
                try {
                    val node = mapper.readTree(candidate)
                    if (node != null && node.isObject) return node
                } catch (_: Exception) {
                }
            }
            return null
        }
    }
}
