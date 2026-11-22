package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.RunStatus
import workflow.engine.Workflow
import workflow.engine.WorkflowNode

@TestConfiguration
class StuckNodeFixture {
    private fun node(kind: String, body: () -> Unit) = object : NodeDefinition {
        override val type = kind
        override val title = kind
        override val category = NodeCategory.LOGIC
        override val inputs = emptyList<workflow.engine.PortSpec>()
        override val outputs = emptyList<workflow.engine.PortSpec>()
        override val paramsSchema = JsonNodeFactory.instance.objectNode()
        override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
            body()
            return NodeOutput(emptyMap())
        }
    }

    /** Блокирующий код, который не реагирует на отмену корутины. */
    @Bean fun blockingNode(): NodeDefinition = node("test.blocking") { Thread.sleep(20_000) }

    @Bean fun overflowNode(): NodeDefinition = node("test.overflow") { throw StackOverflowError() }
}

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:resilience;DB_CLOSE_DELAY=-1",
    "workflow.data-dir=build/resilience-test-data",
    "workflow.run-budget-millis=1500",
])
@Import(StuckNodeFixture::class)
class RunResilienceTest @Autowired constructor(
    private val store: WorkflowStore,
    private val runs: RunService,
    private val history: RunStore,
    private val json: ObjectMapper,
) {
    private fun finish(type: String): Pair<RunRecord, Long> {
        val saved = store.create(Workflow(name = "resilience-$type", nodes = listOf(
            WorkflowNode("start", "trigger.manual"), WorkflowNode("stuck", type),
        )))
        val started = System.nanoTime()
        val ticket = runs.start(requireNotNull(saved.id), json.createObjectNode().put("kind", "manual"))
        var run = history.get(ticket.id)
        while (run.status == RunStatus.RUNNING && System.nanoTime() - started < 8_000_000_000L) {
            Thread.sleep(25)
            run = history.get(ticket.id)
        }
        return run to (System.nanoTime() - started) / 1_000_000
    }

    @Test fun `a node that never returns fails the run at the budget`() {
        val (run, millis) = finish("test.blocking")
        assertEquals(RunStatus.FAILED, run.status)
        assertEquals("Превышено время выполнения: этап stuck", run.error)
        assertTrue(millis < 6_000, "Бюджет 1,5 с, но запуск завершился за $millis мс")
        assertEquals(NodeStatus.FAILED, run.nodeRuns.first { it.nodeId == "stuck" }.status)
    }

    @Test fun `an Error inside a node fails the node and the run completes`() {
        val (run, _) = finish("test.overflow")
        assertNotEquals(RunStatus.RUNNING, run.status)
        assertEquals(NodeStatus.FAILED, run.nodeRuns.first { it.nodeId == "stuck" }.status)
    }
}
