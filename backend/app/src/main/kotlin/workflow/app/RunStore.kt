package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import workflow.engine.Delivery
import workflow.engine.NodeRun
import workflow.engine.RunEvent
import workflow.engine.RunStatus
import java.time.Instant

data class RunRecord(
    val id: String,
    val workflowId: String,
    val workflowVersion: Long,
    val trigger: JsonNode,
    val status: RunStatus,
    val startedAt: Instant,
    val finishedAt: Instant? = null,
    val nodeRuns: List<NodeRun> = emptyList(),
    val report: JsonNode? = null,
    val coverageStatus: String = "PARTIAL",
    val counts: Map<String, Int> = emptyMap(),
    val commitsVerified: Boolean = false,
    val rulesVersions: Set<String> = emptySet(),
    val workflowName: String? = null,
    val error: String? = null,
    val delivery: Delivery? = null,
)

data class StoredEvent(val id: Long, val name: String, val data: JsonNode)

@Repository
class RunStore(private val db: JdbcTemplate, private val json: ObjectMapper) {
    @Transactional
    fun begin(run: RunRecord) {
        db.update("INSERT INTO workflow_runs (id, workflow_id, started_at, state, payload) VALUES (?, ?, ?, ?, ?)",
            run.id, run.workflowId, now(), run.status.name, json.writeValueAsString(run))
        event(run.id, RunEvent("run.status", mapOf("status" to run.status)))
    }

    @Transactional
    fun finish(run: RunRecord) {
        db.update("UPDATE workflow_runs SET state = ?, payload = ? WHERE id = ?",
            run.status.name, json.writeValueAsString(run), run.id)
        event(run.id, RunEvent("run.status", mapOf("status" to run.status, "coverageStatus" to run.coverageStatus,
            "error" to run.error, "delivery" to run.delivery)))
    }

    fun event(id: String, event: RunEvent) {
        db.update("INSERT INTO run_events (run_id, event_name, payload) VALUES (?, ?, ?)",
            id, event.name, json.writeValueAsString(event.data))
    }

    fun events(id: String, after: Long): List<StoredEvent> = db.query(
        "SELECT seq, event_name, payload FROM run_events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT 100",
        { row, _ -> StoredEvent(row.getLong(1), row.getString(2), json.readTree(row.getString(3))) }, id, after,
    )

    fun running(): List<RunRecord> = query("SELECT payload FROM workflow_runs WHERE state = 'RUNNING'")
    fun get(id: String): RunRecord = query("SELECT payload FROM workflow_runs WHERE id = ?", id)
        .singleOrNull() ?: throw MissingResource()

    fun list(workflowId: String?): List<RunRecord> =
        if (workflowId == null) query("SELECT payload FROM workflow_runs ORDER BY started_at DESC, id LIMIT 100")
        else query("SELECT payload FROM workflow_runs WHERE workflow_id = ? ORDER BY started_at DESC, id LIMIT 100", workflowId)

    fun previousComplete(runId: String): RunRecord? = db.queryForStream(
        """
        SELECT prior_run.payload
        FROM workflow_runs prior_run JOIN workflow_runs current_run
          ON current_run.id = ? AND prior_run.workflow_id = current_run.workflow_id
        WHERE prior_run.started_at < current_run.started_at AND prior_run.state = 'SUCCESS'
        ORDER BY prior_run.started_at DESC, prior_run.id
        """.trimIndent(),
        { row, _ -> json.readValue(row.getString(1), RunRecord::class.java) }, runId,
    ).use { records ->
        records.filter { it.coverageStatus == "COMPLETE" && it.report != null }.findFirst().orElse(null)
    }

    private fun query(sql: String, vararg params: Any) = db.query(
        sql, { row, _ -> json.readValue(row.getString(1), RunRecord::class.java) }, *params,
    )
}
