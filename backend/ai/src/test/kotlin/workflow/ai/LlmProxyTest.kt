package workflow.ai

import ru.codeguard.ai.llm.LlmConfig
import ru.codeguard.ai.llm.OpenAiCompatibleClient
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertEquals

class LlmProxyTest {
    private val proxy = "http://127.0.0.1:10809"

    @Test
    fun `внешний провайдер идёт через прокси`() {
        val selector = assertNotNull(OpenAiCompatibleClient.proxySelector(LlmConfig("https://api.groq.com/openai/v1", "m", proxy = proxy)))
        val found = selector.select(java.net.URI.create("https://api.groq.com/openai/v1/chat/completions"))
        assertEquals(java.net.Proxy.Type.HTTP, found.single().type())
        assertEquals(10809, (found.single().address() as java.net.InetSocketAddress).port)
    }

    @Test
    fun `локальная модель всегда напрямую`() {
        for (url in listOf("http://localhost:11434/v1", "http://127.0.0.1:11434/v1", "http://[::1]:8000/v1")) {
            assertNull(OpenAiCompatibleClient.proxySelector(LlmConfig(url, "m", proxy = proxy)), url)
        }
    }

    @Test
    fun `без настройки прокси не используется`() {
        assertNull(OpenAiCompatibleClient.proxySelector(LlmConfig("https://api.groq.com/openai/v1", "m")))
        assertNull(OpenAiCompatibleClient.proxySelector(LlmConfig("https://api.groq.com/openai/v1", "m", proxy = "bad")))
    }

    @Test
    fun `переменная окружения попадает в настройки`() {
        val config = LlmConfig.fromEnv(mapOf("LLM_BASE_URL" to "https://x.test/v1", "LLM_MODEL" to "m", "APP_OUTBOUND_PROXY" to proxy))
        assertEquals(proxy, config?.proxy)
    }
}
