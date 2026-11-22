package workflow.ai

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import ru.codeguard.ai.llm.LlmConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LlmSettingsTest {
    private val secret = "sk-test-0123456789"
    private fun runtime() = LlmRuntime(LlmConfig("https://api.groq.com/openai/v1", "llama-3.3-70b", apiKey = secret))

    @Test
    fun `ответ никогда не содержит ключ`() {
        val view = runtime().settings()
        assertTrue(view.apiKeySet)
        assertFalse(jacksonObjectMapper().writeValueAsString(view).contains(secret))
    }

    @Test
    fun `без ключа в запросе ключ сохраняется для того же сервера`() {
        val rt = runtime()
        val view = rt.update(LlmSettingsUpdate("groq", "https://api.groq.com/openai/v1/", "llama-3.1-8b"))
        assertTrue(view.apiKeySet)
        assertEquals("llama-3.1-8b", rt.client()!!.config.model)
        assertEquals(secret, rt.client()!!.config.apiKey)
    }

    @Test
    fun `смена сервера без нового ключа сбрасывает ключ - его нельзя увести на чужой адрес`() {
        val rt = runtime()
        val view = rt.update(LlmSettingsUpdate("openai-compatible", "https://evil.example/v1", "m"))
        assertFalse(view.apiKeySet)
        assertNull(rt.client()!!.config.apiKey)
    }

    @Test
    fun `переключение на локальную модель - http только для localhost`() {
        val rt = runtime()
        val view = rt.update(LlmSettingsUpdate("ollama", "http://localhost:11434/v1", "qwen2.5-coder:7b"))
        assertEquals("ollama", view.provider)
        assertEquals("http://localhost:11434/v1", rt.client()!!.config.baseUrl)
        assertFalse(view.apiKeySet)
        assertFailsWith<InvalidLlmSettings> { rt.update(LlmSettingsUpdate("ollama", "http://10.0.0.5:11434/v1", "m")) }
        assertFailsWith<InvalidLlmSettings> { rt.update(LlmSettingsUpdate("groq", "https://user:pw@api.groq.com/v1", "m")) }
        assertFailsWith<InvalidLlmSettings> { rt.update(LlmSettingsUpdate("groq", "ftp://api.groq.com", "m")) }
    }

    @Test
    fun `неверные провайдер, модель и ключ отклоняются, текущая настройка не меняется`() {
        val rt = runtime()
        assertFailsWith<InvalidLlmSettings> { rt.update(LlmSettingsUpdate("bard", "https://x.example/v1", "m")) }
        assertFailsWith<InvalidLlmSettings> { rt.update(LlmSettingsUpdate("groq", "https://x.example/v1", "")) }
        assertFailsWith<InvalidLlmSettings> { rt.update(LlmSettingsUpdate("groq", "https://x.example/v1", "m", "a b")) }
        assertEquals("https://api.groq.com/openai/v1", rt.client()!!.config.baseUrl)
        assertEquals(secret, rt.client()!!.config.apiKey)
    }

    @Test
    fun `без настроек при старте - пустой ответ, после сохранения клиент появляется`() {
        val rt = LlmRuntime(null)
        assertEquals(LlmSettingsView("openai-compatible", "", "", false), rt.settings())
        assertNull(rt.client())
        rt.update(LlmSettingsUpdate("ollama", "http://127.0.0.1:11434/v1", "qwen2.5-coder:1.5b"))
        assertEquals("qwen2.5-coder:1.5b", rt.client()!!.config.model)
    }

    @Test
    fun `адрес с учётными данными или ключом из env не отдаётся`() {
        assertEquals("", LlmRuntime(LlmConfig("https://u:p@llm.example/v1", "m", apiKey = secret)).settings().baseUrl)
        assertEquals("", LlmRuntime(LlmConfig("https://llm.example/v1?sig=abc", "m")).settings().baseUrl)
        assertEquals("", LlmRuntime(LlmConfig("https://llm.example/$secret/v1", "m", apiKey = secret)).settings().baseUrl)
    }
}
