package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.scheduling.support.CronExpression
import org.springframework.stereotype.Component
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

@Component
class Scheduler(
    private val workflows: WorkflowStore,
    private val runs: RunService,
    private val db: JdbcTemplate,
    private val json: ObjectMapper,
    private val demo: DemoMode,
) {
    private var checked = Instant.now().truncatedTo(ChronoUnit.SECONDS)

    @Scheduled(fixedDelay = 500)
    fun due() {
        if (demo.enabled) return // в публичном демо запуски только по действию посетителя, с лимитами
        val end = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        if (end <= checked) return
        val start = maxOf(checked, end.minusSeconds(60))
        checked = end
        for (summary in workflows.list()) {
            val workflow = runCatching { workflows.get(summary.id) }.getOrNull() ?: continue
            for (node in workflow.nodes.filter { it.type == "trigger.cron" }) {
                val zone = runCatching { ZoneId.of(node.params.path("zone").asText("Europe/Moscow")) }.getOrNull() ?: continue
                val cron = runCatching { CronExpression.parse(node.params.path("cron").asText()) }.getOrNull() ?: continue
                val next = cron.next(start.atZone(zone))?.toInstant() ?: continue
                if (next > end) continue
                val fireAt = next.atOffset(ZoneOffset.UTC)
                try {
                    db.update("INSERT INTO schedules(workflow_id, node_id, fire_at) VALUES (?, ?, ?)", summary.id, node.id, fireAt)
                } catch (_: DuplicateKeyException) {
                    continue
                }
                val trigger = json.createObjectNode().put("kind", "cron").put("scheduledAt", next.toString())
                runs.startScheduled(workflow, trigger, node.id)
            }
        }
    }
}
