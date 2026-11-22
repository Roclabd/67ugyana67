package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.*
import workflow.engine.*
import workflow.nodes.InputRejected
import workflow.nodes.PublicNetwork
import workflow.nodes.findingsOf
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

internal const val REVIEW_WAIT_NODE = "approval.wait"
internal const val MAX_REVIEW_WAIT_SECONDS = 300L
internal fun reviewWaitSeconds(params: JsonNode): Long =
    params.path("timeoutSeconds").asLong(180).coerceIn(1, MAX_REVIEW_WAIT_SECONDS)

enum class ReviewChoice(val port: String) {
    ACCEPT_RISK("accepted"), CREATE_TASK("task"), VIEW_REMEDIATION("remediation"),
}

data class ReviewDecision(val choice: ReviewChoice, val reason: String? = null)

@Service
class ReviewDecisions(
    private val json: ObjectMapper,
    private val access: ReviewAccess,
    private val history: FindingHistory,
    private val runs: RunStore,
    @Value("\${TELEGRAM_BOT_TOKEN:}") private val bot: String,
    @Value("\${TELEGRAM_CHAT_ID:}") private val chat: String,
    @Value("\${TELEGRAM_APPROVER_USER_ID:}") approver: String,
    @Value("\${TELEGRAM_APPROVAL_WEBHOOK_SECRET:}") private val webhookSecret: String,
) {
    private val approverId = approver.toLongOrNull() ?: chat.toLongOrNull()?.takeIf { it > 0 }
    private val telegramEnabled = bot.isNotBlank() && chat.isNotBlank() && approverId != null && webhookSecret.isNotBlank()
    private val pending = ConcurrentHashMap<String, CompletableDeferred<ReviewDecision>>()
    private val explicitAcceptances = ConcurrentHashMap<String, ConcurrentLinkedQueue<RiskAcceptance>>()

    suspend fun waitFor(ctx: NodeContext, fingerprint: String, seconds: Long): ReviewDecision {
        val id = UUID.randomUUID().toString()
        val gate = CompletableDeferred<ReviewDecision>()
        pending[id] = gate
        try {
            ctx.log("Ожидается решение по находке. Идентификатор запроса: $id")
            if (telegramEnabled) withContext(Dispatchers.IO) {
                try {
                    telegram("sendMessage", mapOf(
                        "chat_id" to chat,
                        "text" to "Проверка требует решения. Запуск ${ctx.runId}, находка ${fingerprint.take(12)}.",
                        "reply_markup" to mapOf("inline_keyboard" to listOf(
                            listOf(button("Принять риск", "risk", id), button("Создать задачу", "task", id)),
                            listOf(button("Показать рекомендацию", "fix", id)),
                        )),
                    ))
                } catch (cancel: CancellationException) {
                    throw cancel
                } catch (_: Exception) {
                    ctx.log("Telegram не принял запрос. Решение доступно через API.")
                }
            }
            val decision = withTimeoutOrNull(seconds * 1000) { gate.await() }
                ?: throw NodeFailure("Истекло время ожидания решения.")
            if (decision.choice == ReviewChoice.ACCEPT_RISK) {
                explicitAcceptances.computeIfAbsent(ctx.runId) { ConcurrentLinkedQueue() }
                    .add(RiskAcceptance(ctx.runId, fingerprint, requireNotNull(decision.reason)))
            }
            return decision
        } finally {
            pending.remove(id)
        }
    }

    fun decide(id: String, decision: ReviewDecision) {
        val gate = pending[id] ?: throw MissingResource()
        val reason = decision.reason?.trim()
        if (reason != null && reason.length > 300 || decision.choice == ReviewChoice.ACCEPT_RISK && reason.isNullOrBlank()) {
            throw InputRejected("Укажите причину принятия риска до 300 символов.")
        }
        if (!gate.complete(decision.copy(reason = reason))) throw Conflict("Решение уже принято.")
    }

    @Transactional
    fun finish(run: RunRecord) {
        runs.finish(run)
        val choices = explicitAcceptances.remove(run.id) ?: return
        if (run.status != RunStatus.SUCCESS || run.coverageStatus != "COMPLETE") return
        for (choice in choices) {
            try {
                history.acceptRisk(run.workflowId, choice)
            } catch (_: InputRejected) {
                // The workflow may have changed before its run finished.
            } catch (_: MissingResource) {
                // The workflow may have been deleted.
            }
        }
    }

    fun onTelegram(secret: String?, update: JsonNode) {
        if (!telegramEnabled || !access.matches(secret, webhookSecret)) throw ReviewDenied()
        val callback = update.path("callback_query")
        if (callback.isObject) {
            if (callback.path("from").path("id").asLong() != approverId ||
                callback.path("message").path("chat").path("id").asText() != chat) return
            val parts = callback.path("data").asText().split(':', limit = 3)
            if (parts.size != 3 || parts[0] != "review") return
            val id = parts[2]
            val answer = try {
                when (parts[1]) {
                    "risk" -> if (id in pending.keys) "Отправьте /accept_risk $id и причину через пробел." else "Запрос уже закрыт."
                    "task" -> { decide(id, ReviewDecision(ReviewChoice.CREATE_TASK)); "Решение записано." }
                    "fix" -> { decide(id, ReviewDecision(ReviewChoice.VIEW_REMEDIATION)); "Решение записано." }
                    else -> return
                }
            } catch (_: MissingResource) {
                "Запрос уже закрыт."
            } catch (_: Conflict) {
                "Решение уже принято."
            }
            runCatching {
                telegram("answerCallbackQuery", mapOf("callback_query_id" to callback.path("id").asText(), "text" to answer))
            }
            return
        }
        val message = update.path("message")
        if (message.path("from").path("id").asLong() != approverId || message.path("chat").path("id").asText() != chat) return
        val parts = message.path("text").asText().trim().split(Regex("\\s+"), limit = 3)
        if (parts.size == 3 && parts[0].substringBefore('@') == "/accept_risk") {
            runCatching { decide(parts[1], ReviewDecision(ReviewChoice.ACCEPT_RISK, parts[2])) }
        }
    }

    private fun button(label: String, choice: String, id: String) =
        mapOf("text" to label, "callback_data" to "review:$choice:$id")

    private fun telegram(method: String, payload: Map<String, Any>) {
        require(Regex("[0-9]+:[A-Za-z0-9_-]{15,120}").matches(bot))
        PublicNetwork.post("https://api.telegram.org/bot$bot/$method", json.writeValueAsString(payload))
    }
}

@Configuration(proxyBeanMethods = false)
class ReviewDecisionNodes {
    @Bean
    fun waitForDecision(decisions: ReviewDecisions, json: ObjectMapper): NodeDefinition = object : NodeDefinition {
        override val type = REVIEW_WAIT_NODE
        override val title = "Ожидать решения"
        override val category = NodeCategory.LOGIC
        override val inputs = listOf(PortSpec("findings", PortType.FINDINGS))
        override val outputs = ReviewChoice.entries.map { PortSpec(it.port, PortType.DECISION, false) }
        override val paramsSchema: JsonNode = json.readTree("""
            {"type":"object","properties":{"fingerprint":{"type":"string","maxLength":160},
            "timeoutSeconds":{"type":"integer","minimum":1,"maximum":$MAX_REVIEW_WAIT_SECONDS}},"additionalProperties":false}
        """.trimIndent())

        override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
            val known = findingsOf(json.valueToTree(input.ports["findings"]))
            if (known.isEmpty()) return NodeOutput(emptyMap(), NodeStatus.SKIPPED)
            val snapshot = ctx.analysis
            if (ctx.coverageStatus != "COMPLETE" || snapshot == null) throw NodeFailure("Для решения нужна завершённая проверка.")
            val fingerprint = ctx.params.path("fingerprint").textValue() ?: known.first().path("fingerprint").asText()
            if (fingerprint !in snapshot.fingerprints || known.none { it.path("fingerprint").asText() == fingerprint }) {
                throw NodeFailure("Находка отсутствует в результатах этой проверки.")
            }
            val decision = decisions.waitFor(ctx, fingerprint, reviewWaitSeconds(ctx.params))
            return NodeOutput(mapOf(decision.choice.port to mapOf("fingerprint" to fingerprint)))
        }
    }
}

@RestController
@RequestMapping("/api")
class ReviewDecisionController(private val decisions: ReviewDecisions, private val access: ReviewAccess) {
    @PostMapping("/approvals/{id}/decision")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun decide(@PathVariable id: String, @RequestBody request: ReviewDecision,
        @RequestHeader("Authorization", required = false) authorization: String?) {
        access.check(authorization)
        decisions.decide(id, request)
    }

    @PostMapping("/telegram/approvals")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun telegram(@RequestHeader("X-Telegram-Bot-Api-Secret-Token", required = false) secret: String?,
        @RequestBody update: JsonNode) = decisions.onTelegram(secret, update)
}
