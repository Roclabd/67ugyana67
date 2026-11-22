package workflow.engine

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory

data class Workflow(
    val id: String? = null,
    val name: String,
    val version: Long = 0,
    val nodes: List<WorkflowNode> = emptyList(),
    val edges: List<WorkflowEdge> = emptyList(),
    /** Проект, которому принадлежит сценарий (ZIP-проект); null - обычный сценарий или проект-репозиторий. */
    val project: ProjectMeta? = null,
)

data class ProjectMeta(val kind: String, val name: String)

data class WorkflowNode(
    val id: String,
    val type: String,
    val params: JsonNode = JsonNodeFactory.instance.objectNode(),
    val position: Position = Position(),
    val continueOnError: Boolean = false,
)

data class Position(val x: Double = 0.0, val y: Double = 0.0)
data class Endpoint(val node: String, val port: String)
data class WorkflowEdge(val id: String, val from: Endpoint, val to: Endpoint)
data class GraphError(
    val code: String,
    val message: String,
    val nodeId: String? = null,
    val edgeId: String? = null,
    val port: String? = null,
)

class InvalidGraph(val errors: List<GraphError>) : RuntimeException("Сценарий не прошёл проверку")

internal fun Workflow.layers(): List<List<WorkflowNode>> {
    val incoming = edges.groupingBy { it.to.node }.eachCount().toMutableMap()
    val outgoing = edges.groupBy { it.from.node }
    val layers = mutableListOf<List<WorkflowNode>>()
    var ready = nodes.filter { incoming[it.id] == null }
    val byId = nodes.associateBy { it.id }
    while (ready.isNotEmpty()) {
        layers.add(ready)
        val next = mutableListOf<WorkflowNode>()
        for (node in ready) {
            for (edge in outgoing[node.id].orEmpty()) {
                val id = edge.to.node
                val remaining = incoming.getValue(id) - 1
                incoming[id] = remaining
                if (remaining == 0) next.add(byId.getValue(id))
            }
        }
        ready = next.sortedBy { it.id }
    }
    return layers
}
