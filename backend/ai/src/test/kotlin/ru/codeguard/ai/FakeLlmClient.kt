package ru.codeguard.ai

import ru.codeguard.ai.llm.ChatMessage
import ru.codeguard.ai.llm.LlmClient
import ru.codeguard.ai.llm.LlmConfig
import ru.codeguard.ai.llm.LlmReply

/** Подставной клиент: отдаёт ответы по очереди (лямбда может бросить LlmUnavailableException), запоминает все запросы. */
class FakeLlmClient(override val config: LlmConfig, private val replies: MutableList<() -> String>) : LlmClient {
    /** Копии messages каждого вызова chat — в порядке вызовов. */
    val received = mutableListOf<List<ChatMessage>>()
    val callCount: Int get() = received.size

    override fun chat(messages: List<ChatMessage>): LlmReply {
        received += messages.toList()
        check(replies.isNotEmpty()) { "FakeLlmClient: сценарий ответов исчерпан (вызов №$callCount)" }
        return LlmReply(replies.removeAt(0)(), null, null)
    }

    /** Весь текст всех сообщений всех запросов. */
    fun allText(): String = received.flatten().joinToString("\n") { it.content }
}
