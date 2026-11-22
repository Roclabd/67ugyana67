package workflow.engine

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.NullNode
import com.fasterxml.jackson.databind.node.TextNode

class Expressions(private val json: ObjectMapper) {
    private val expression = Regex("""\{\{\s*([\w-]+(?:\.[\w-]+)*)\s*}}""")

    fun resolveParams(value: JsonNode, secretParams: Set<String>, roots: Map<String, JsonNode>): JsonNode =
        json.createObjectNode().also { result ->
            value.fields().forEach { (key, child) ->
                result.set<JsonNode>(key, if (key in secretParams) child else resolve(child, roots))
            }
        }

    fun resolve(value: JsonNode, roots: Map<String, JsonNode>): JsonNode = when {
        value.isObject -> json.createObjectNode().also { result ->
            value.fields().forEach { (key, child) -> result.set<JsonNode>(key, resolve(child, roots)) }
        }
        value.isArray -> json.createArrayNode().also { result -> value.forEach { result.add(resolve(it, roots)) } }
        value.isTextual -> {
            val text = value.textValue()
            val exact = expression.matchEntire(text)
            when {
                exact != null -> lookup(exact.groupValues[1], roots)
                "{{" in text -> TextNode.valueOf(expression.replace(text) { match ->
                    val item = lookup(match.groupValues[1], roots)
                    if (item.isContainerNode) item.toString() else item.asText()
                }.also { require("{{" !in it) })
                else -> value
            }
        }
        else -> value
    }

    private fun lookup(path: String, roots: Map<String, JsonNode>): JsonNode {
        val parts = path.split('.')
        var value = roots[parts.first()] ?: NullNode.instance
        for (part in parts.drop(1)) {
            value = if (value.isArray) part.toIntOrNull()?.let { value[it] } ?: NullNode.instance
            else value[part] ?: NullNode.instance
        }
        require(!value.isMissingNode && !value.isNull) { "Expression value unavailable" }
        return value
    }
}
