package ru.codeguard.ai

import ru.codeguard.ai.llm.ChatMessage
import ru.codeguard.ai.llm.Checked
import ru.codeguard.ai.llm.FileResponseCache
import ru.codeguard.ai.llm.JsonCompletion
import ru.codeguard.ai.llm.LlmConfig
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CacheSanitizationTest {
    @Test
    fun secretLikeStringInModelReplyDoesNotReachCacheFile() {
        val secret = "sk-Zx81QwErTy93LmNbVc54AsDf"
        val dir = Files.createTempDirectory("llm-cache")
        val client = FakeLlmClient(LlmConfig("http://x", "m"), mutableListOf({ """{"text":"use token=$secret and Bearer $secret here","ok":1}""" }))
        val outcome = JsonCompletion(client, FileResponseCache(dir)).complete("t", "v1", listOf(ChatMessage("user", "q"))) { node ->
            Checked.Ok(node.path("ok").asInt())
        }
        assertEquals(1, outcome.value)
        val files = Files.list(dir).use { it.toList() }
        assertEquals(1, files.size)
        val stored = Files.readString(files[0])
        assertFalse(secret in stored, stored)
        assertTrue("ok" in stored)
    }
}
