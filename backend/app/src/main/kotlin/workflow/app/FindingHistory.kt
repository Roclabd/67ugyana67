package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.*
import workflow.engine.*
import workflow.nodes.InputRejected
import workflow.nodes.findingsOf
import java.security.MessageDigest
import java.util.HexFormat

class ReviewDenied : RuntimeException()

@Component
class ReviewAccess(@Value("\${APP_REVIEW_TOKEN:}") private val token: String) {
    fun check(authorization: String?) {
        val value = authorization?.takeIf { it.startsWith("Bearer ") }?.substring(7)
        if (!matches(value, token)) throw ReviewDenied()
    }

    internal fun matches(provided: String?, expected: String): Boolean =
        expected.isNotBlank() && !provided.isNullOrBlank() &&
            MessageDigest.isEqual(expected.toByteArray(Charsets.UTF_8), provided.toByteArray(Charsets.UTF_8))
}

data class BaselineUpdate(val runId: String)
data class RiskAcceptance(val runId: String, val fingerprint: String, val reason: String)

@Service
class FindingHistory(
    private val db: JdbcTemplate,
    private val workflows: ObjectProvider<WorkflowStore>,
    private val runs: RunStore,
    private val executor: ObjectProvider<DagExecutor>,
) {
    fun setBaseline(workflowId: String, runId: String) {
        checkedSnapshot(workflowId, runs.get(runId))
        db.update("MERGE INTO review_baselines (workflow_id, run_id) KEY (workflow_id) VALUES (?, ?)", workflowId, runId)
    }

    fun acceptRisk(workflowId: String, request: RiskAcceptance) {
        val reason = request.reason.trim()
        if (reason.isEmpty() || reason.length > 300) throw InputRejected("Укажите причину принятия риска до 300 символов.")
        val run = runs.get(request.runId)
        val snapshot = checkedSnapshot(workflowId, run)
        if (request.fingerprint !in snapshot.fingerprints) throw InputRejected("Находка отсутствует в проверенном отчёте.")
        db.update(
            "MERGE INTO accepted_risks (workflow_id, scope_key, fingerprint, run_id, reason) " +
                "KEY (workflow_id, scope_key, fingerprint) VALUES (?, ?, ?, ?, ?)",
            workflowId, scopeKey(snapshot), request.fingerprint, request.runId, reason,
        )
    }

    fun changes(snapshot: AnalysisSnapshot, known: List<JsonNode>): NodeOutput {
        val baselineId = db.query("SELECT run_id FROM review_baselines WHERE workflow_id = ?",
            { row, _ -> row.getString(1) }, snapshot.workflowId).firstOrNull()
        val baseline = baselineId?.let { id ->
            try {
                checkedSnapshot(snapshot.workflowId, runs.get(id)).takeIf { scopeKey(it) == scopeKey(snapshot) }
            } catch (_: InputRejected) {
                null
            } catch (_: MissingResource) {
                null
            }
        }
        val accepted = db.query("SELECT fingerprint FROM accepted_risks WHERE workflow_id = ? AND scope_key = ?",
            { row, _ -> row.getString(1) }, snapshot.workflowId, scopeKey(snapshot)).toSet()
        val previous = baseline?.fingerprints ?: emptySet()
        val fresh = known.filter { it.path("fingerprint").asText() !in previous && it.path("fingerprint").asText() !in accepted }
        val details = mapOf("state" to when {
            baseline != null -> "COMPLETE"
            baselineId != null -> "BASELINE_STALE"
            else -> "BASELINE_REQUIRED"
        }, "removedFingerprints" to baseline?.let { (it.fingerprints - snapshot.fingerprints).sorted() },
            "accepted" to (accepted intersect snapshot.fingerprints).size)
        return NodeOutput(mapOf("findings" to fresh, "details" to details))
    }

    private fun checkedSnapshot(workflowId: String, run: RunRecord): AnalysisSnapshot {
        val workflow = workflows.getObject().get(workflowId)
        val report = run.report
        val snapshot = executor.getObject().analysisSnapshot(workflow, run.nodeRuns)
        val signature = snapshot?.let { rulesVersionSignature(it.rulesVersions) }
        if (run.workflowId != workflowId || workflow.version != run.workflowVersion ||
            run.status != RunStatus.SUCCESS || run.coverageStatus != "COMPLETE" ||
            report?.path("coverage")?.path("status")?.asText() != "COMPLETE" || snapshot == null || signature == null ||
            report.path("inputHash").asText() != snapshot.inputHash ||
            report.path("rulesVersion").textValue() != signature
        ) throw InputRejected("Нужен завершённый отчёт с полным покрытием для текущей версии сценария.")
        return snapshot
    }

    private fun scopeKey(snapshot: AnalysisSnapshot): String = HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256").digest(
            "${snapshot.workflowVersion}\u0000${snapshot.sourceKey}\u0000${rulesVersionSignature(snapshot.rulesVersions)}"
                .toByteArray(Charsets.UTF_8),
        ),
    )
}

@Configuration(proxyBeanMethods = false)
class FindingHistoryNodes {
    @Bean
    fun onlyNew(history: FindingHistory, json: ObjectMapper): NodeDefinition = object : NodeDefinition {
        override val type = "logic.only-new"
        override val title = "Только новое"
        override val category = NodeCategory.LOGIC
        override val inputs = listOf(PortSpec("findings", PortType.FINDINGS))
        override val outputs = listOf(PortSpec("findings", PortType.FINDINGS), PortSpec("details", PortType.ANY))
        override val paramsSchema: JsonNode = JsonNodeFactory.instance.objectNode()
            .put("type", "object").put("additionalProperties", false)

        override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
            val known = findingsOf(json.valueToTree(input.ports["findings"]))
            val snapshot = ctx.analysis
            if (ctx.coverageStatus != "COMPLETE" || snapshot == null ||
                known.map { it.path("fingerprint").asText() }.toSet() != snapshot.fingerprints
            ) return NodeOutput(mapOf("findings" to known, "details" to mapOf("state" to "INCOMPLETE")),
                NodeStatus.PARTIAL)
            return history.changes(snapshot, known)
        }
    }
}

@RestController
@RequestMapping("/api/workflows/{id}")
class FindingHistoryController(private val history: FindingHistory, private val access: ReviewAccess) {
    @PostMapping("/baseline")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun baseline(@PathVariable id: String, @RequestBody request: BaselineUpdate,
        @RequestHeader("Authorization", required = false) authorization: String?) {
        access.check(authorization)
        history.setBaseline(id, request.runId)
    }

    @PostMapping("/risks")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun accept(@PathVariable id: String, @RequestBody request: RiskAcceptance,
        @RequestHeader("Authorization", required = false) authorization: String?) {
        access.check(authorization)
        history.acceptRisk(id, request)
    }
}
