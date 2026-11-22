package workflow.analyzers.secret

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import workflow.engine.DagExecutor
import workflow.engine.Endpoint
import workflow.engine.GraphValidator
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeRegistry
import workflow.engine.PortSpec
import workflow.engine.PortType
import workflow.engine.Redaction
import workflow.engine.RunEvent
import workflow.engine.RunStatus
import workflow.engine.Workflow
import workflow.engine.WorkflowEdge
import workflow.engine.WorkflowNode
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant

class SecretRedactionTest {
    @TempDir lateinit var directory: Path

    @Test
    fun syntheticMatchIsMaskedInNodeOutputAndAbsentFromRunMetadataAndEvents() {
        val rawMatch = "synthetic-redaction-value-27183"
        val pattern = "synthetic-redaction-value-[0-9]+"
        Files.writeString(directory.resolve("app.properties"), "setting=$rawMatch")

        val mapper = ObjectMapper().registerModule(
            SimpleModule().addSerializer(Instant::class.java, ToStringSerializer.instance)
        )
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val source = object : NodeDefinition {
                override val type = "test.model"
                override val title = "Test model"
                override val category = NodeCategory.LOGIC
                override val inputs = emptyList<PortSpec>()
                override val outputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
                override val paramsSchema = mapper.createObjectNode().put("type", "object")

                override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
                    ctx.log("Test pattern: $pattern")
                    return NodeOutput(mapOf("model" to model))
                }
            }
            val node = SecretNode(custom = true)
            val workflow = Workflow(
                name = "Secret redaction",
                nodes = listOf(
                    WorkflowNode("source", source.type),
                    WorkflowNode("secret", node.type, params = mapper.createObjectNode().put("pattern", pattern)),
                ),
                edges = listOf(WorkflowEdge("model", Endpoint("source", "model"), Endpoint("secret", "model"))),
            )
            val registry = NodeRegistry(listOf(source, node))
            val events = mutableListOf<RunEvent>()
            val execution = runBlocking {
                DagExecutor(registry, GraphValidator(registry), mapper).execute(
                    workflow, "test", mapper.createObjectNode(), directory, Redaction(mapper, listOf(pattern)),
                    events::add,
                )
            }

            assertEquals(RunStatus.SUCCESS, execution.status)
            val secretRun = execution.nodeRuns.single { it.nodeId == "secret" }
            val finding = (secretRun.output.getValue("findings") as JsonNode).single()
            assertEquals("custom-regex", finding.path("class").asText())
            assertEquals("****", finding.path("secretMasked").asText())
            assertFalse(finding.has("secretHash"))
            assertEquals(mapOf("kind" to "PROJECT_MODEL"), secretRun.input.getValue("model"))
            assertEquals(listOf("Test pattern: ${Redaction.MASK}"), execution.nodeRuns.first().logs)

            val serializedEvents = events.map { event -> mapper.valueToTree<JsonNode>(event) }
            val secretIo = serializedEvents.single {
                it.path("name").asText() == "node.io" && it.path("data").path("nodeId").asText() == "secret"
            }
            assertEquals(finding, secretIo.path("data").path("output").path("findings").single())
            assertTrue(serializedEvents.any {
                it.path("name").asText() == "log" &&
                    it.path("data").path("message").asText() == "Test pattern: ${Redaction.MASK}"
            })

            val surfaces = mapOf(
                "node output" to mapper.writeValueAsString(secretRun.output),
                "run metadata" to mapper.writeValueAsString(execution),
                "event payloads" to mapper.writeValueAsString(serializedEvents),
            )
            for ((name, payload) in surfaces) {
                assertFalse(payload.contains(rawMatch), "Raw match leaked in $name")
                assertFalse(payload.contains(pattern), "Configured pattern leaked in $name")
            }
        }
    }
}
