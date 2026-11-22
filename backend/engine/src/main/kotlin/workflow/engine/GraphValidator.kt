package workflow.engine

import com.fasterxml.jackson.databind.JsonNode
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion

class GraphValidator(private val registry: NodeRegistry) {
    private val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
    private val schemas = registry.nodes.associate { it.type to factory.getSchema(it.paramsSchema) }

    fun parameterErrors(type: String, params: JsonNode): List<String> {
        val errors = schemas.getValue(type).validate(params).map { it.message }.sorted()
        if (errors.isNotEmpty()) return errors
        return if (registry[type]?.validateParams(params) == true) emptyList() else listOf("Invalid parameters")
    }

    fun validate(workflow: Workflow): List<GraphError> = buildList {
        if (workflow.name.isBlank() || workflow.name.length > 160) {
            add(GraphError("INVALID_NAME", "Укажите название до 160 символов"))
        }
        if (workflow.nodes.size > 100 || workflow.edges.size > 300) {
            add(GraphError("GRAPH_LIMIT", "Лимит сценария: 100 нод и 300 связей"))
            return@buildList
        }
        val nodes = workflow.nodes.associateBy { it.id }
        val connected = mutableSetOf<Endpoint>()
        val edgeIds = mutableSetOf<String>()
        for (node in workflow.nodes) {
            val definition = registry[node.type]
            if (!identifier.matches(node.id)) add(GraphError("INVALID_ID", "Недопустимый ID ноды", node.id))
            if (definition == null) {
                add(GraphError("UNKNOWN_NODE", "Тип ноды отсутствует в каталоге", node.id))
            } else if (!node.params.isObject || parameterErrors(node.type, node.params).isNotEmpty()) {
                // Schema errors can echo user input. Never include raw parameter values in API errors.
                add(GraphError("INVALID_PARAMS", "Параметры ноды должны соответствовать схеме каталога", node.id))
            } else if (definition.secretParams.any { node.params.has(it) && !node.params[it].isTextual }) {
                add(GraphError("INVALID_SECRET", "Секретный параметр должен быть строкой", node.id))
            }
        }
        if (nodes.size != workflow.nodes.size) add(GraphError("DUPLICATE_NODE", "ID нод должны быть уникальными"))
        for (edge in workflow.edges) {
            if (!identifier.matches(edge.id) || !edgeIds.add(edge.id)) {
                add(GraphError("INVALID_EDGE_ID", "ID связей должны быть допустимыми и уникальными", edgeId = edge.id))
            }
            val from = nodes[edge.from.node]?.let { registry[it.type] }
                ?.outputs?.find { it.name == edge.from.port }
            val to = nodes[edge.to.node]?.let { registry[it.type] }
                ?.inputs?.find { it.name == edge.to.port }
            when {
                from == null || to == null ->
                    add(GraphError("UNKNOWN_PORT", "Связь ссылается на отсутствующий порт", edgeId = edge.id))
                from.type != to.type && from.type != PortType.ANY && to.type != PortType.ANY ->
                    add(GraphError("PORT_TYPE", "Типы портов несовместимы", edgeId = edge.id))
                !connected.add(edge.to) ->
                    add(GraphError("DUPLICATE_INPUT", "К входному порту уже подключена связь", edgeId = edge.id))
            }
        }
        for (node in workflow.nodes) {
            registry[node.type]?.inputs.orEmpty().filter { it.required }.forEach { port ->
                if (Endpoint(node.id, port.name) !in connected) {
                    add(GraphError("REQUIRED_INPUT", "Подключите вход ${port.name}", node.id, port = port.name))
                }
            }
        }
        val knownEdges = workflow.edges.filter { it.from.node in nodes && it.to.node in nodes }
        if (nodes.size == workflow.nodes.size && workflow.copy(edges = knownEdges).layers().sumOf { it.size } != nodes.size) {
            val outgoing = knownEdges.groupBy { it.from.node }
            for (edge in knownEdges) {
                if (reaches(edge.to.node, edge.from.node, outgoing)) {
                    add(GraphError("CYCLE", "Связь входит в цикл", edgeId = edge.id))
                }
            }
        }
    }

    private fun reaches(start: String, target: String, outgoing: Map<String, List<WorkflowEdge>>): Boolean {
        val pending = ArrayDeque(listOf(start))
        val seen = mutableSetOf<String>()
        while (pending.isNotEmpty()) {
            val node = pending.removeFirst()
            if (node == target) return true
            if (seen.add(node)) pending.addAll(outgoing[node].orEmpty().map { it.to.node })
        }
        return false
    }

    fun requireValid(workflow: Workflow) {
        val errors = validate(workflow)
        if (errors.isNotEmpty()) throw InvalidGraph(errors)
    }

    companion object {
        private val identifier = Regex("[A-Za-z0-9_-]{1,100}")
    }
}
