package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import workflow.engine.*

private val json = ObjectMapper()
fun schema(source: String): JsonNode = json.readTree(source)

internal class PlatformNode(
    override val type: String,
    override val title: String,
    override val category: NodeCategory,
    override val inputs: List<PortSpec> = emptyList(),
    override val outputs: List<PortSpec> = emptyList(),
    override val paramsSchema: JsonNode = schema("""{"type":"object","additionalProperties":false}"""),
    override val secretParams: Set<String> = emptySet(),
    private val valid: (JsonNode) -> Boolean = { true },
    override val description: String? = null,
    override val notifyOnFailure: Boolean = false,
    private val action: suspend (NodeContext, NodeInput) -> NodeOutput,
) : NodeDefinition {
    override fun validateParams(params: JsonNode) = valid(params)
    override suspend fun run(ctx: NodeContext, input: NodeInput) = action(ctx, input)
}

fun result(port: String, value: Any?) = NodeOutput(mapOf(port to value))
