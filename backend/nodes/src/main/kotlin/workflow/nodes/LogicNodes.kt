package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.re2j.Pattern
import kotlinx.coroutines.delay
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.support.CronExpression
import workflow.engine.*
import java.time.ZoneId

@Configuration(proxyBeanMethods = false)
class LogicNodes(private val json: ObjectMapper) {
    @Bean fun manualTrigger(): NodeDefinition = trigger("manual", "Ручной запуск")
    @Bean fun webhookTrigger(): NodeDefinition = trigger("webhook", "Входящий вебхук")
    @Bean fun cronTrigger(): NodeDefinition = trigger("cron", "По расписанию", schema("""
        {"type":"object","properties":{"cron":{"type":"string","maxLength":100,"format":"cron"},
        "zone":{"type":"string","maxLength":80}},"required":["cron"],"additionalProperties":false}
    """)) { params -> runCatching {
        CronExpression.parse(params.path("cron").asText())
        ZoneId.of(params.path("zone").asText("Europe/Moscow"))
    }.isSuccess }

    private fun trigger(kind: String, title: String,
        params: JsonNode = schema("""{"type":"object","additionalProperties":false}"""),
        valid: (JsonNode) -> Boolean = { true },
    ) =
        PlatformNode("trigger.$kind", title, NodeCategory.TRIGGER,
            outputs = listOf(PortSpec("trigger", PortType.ANY)), paramsSchema = params, valid = valid) { ctx, _ ->
            val requested = ctx.trigger.path("triggerNodeId").textValue()
            if (ctx.trigger.path("kind").asText() == kind && (requested == null || requested == ctx.nodeId))
                result("trigger", ctx.trigger)
            else NodeOutput(emptyMap(), NodeStatus.SKIPPED)
        }

    @Bean fun branch(): NodeDefinition = PlatformNode(
        "logic.if", "Если / иначе", NodeCategory.LOGIC,
        inputs = listOf(PortSpec("decision", PortType.DECISION), PortSpec("value", PortType.ANY, false)),
        outputs = listOf(PortSpec("true", PortType.ANY, false), PortSpec("false", PortType.ANY, false)),
    ) { _, input ->
        val decision = json.valueToTree<JsonNode>(input.ports["decision"])
        require(decision.isBoolean)
        result(decision.asText(), input.ports.getOrDefault("value", decision))
    }

    @Bean fun comparison(): NodeDefinition = PlatformNode(
        "logic.compare", "Сравнение", NodeCategory.LOGIC,
        inputs = listOf(PortSpec("value", PortType.ANY, false)),
        outputs = listOf(PortSpec("decision", PortType.DECISION)),
        paramsSchema = schema("""{"type":"object","properties":{
        "left":{},"right":{},"operator":{"enum":["eq","ne","gt","gte","lt","lte"]}},
        "required":["right","operator"],"additionalProperties":false}"""),
    ) { ctx, input ->
        val left = ctx.params["left"] ?: json.valueToTree<JsonNode>(input.ports["value"])
        val right = ctx.params["right"]
        val operator = ctx.params["operator"].asText()
        val equal = if (left.isNumber && right.isNumber) left.decimalValue().compareTo(right.decimalValue()) == 0
            else left == right
        val decision = when (operator) {
            "eq" -> equal
            "ne" -> !equal
            else -> {
                require(left.isNumber && right.isNumber)
                val cmp = left.decimalValue().compareTo(right.decimalValue())
                when (operator) { "gt" -> cmp > 0; "gte" -> cmp >= 0; "lt" -> cmp < 0; else -> cmp <= 0 }
            }
        }
        result("decision", decision)
    }

    @Bean fun regex(): NodeDefinition = PlatformNode(
        "logic.regex", "Регулярное выражение", NodeCategory.LOGIC,
        inputs = listOf(PortSpec("value", PortType.ANY, false)),
        outputs = listOf(PortSpec("decision", PortType.DECISION)),
        paramsSchema = schema("""{"type":"object","properties":{"pattern":{"type":"string","maxLength":256},
        "text":{"type":"string","maxLength":16384}},"required":["pattern"],"additionalProperties":false}"""),
    ) { ctx, input ->
        val text = ctx.params["text"]?.asText() ?: json.valueToTree<JsonNode>(input.ports["value"]).asText()
        require(text.length <= 16_384)
        result("decision", Pattern.compile(ctx.params["pattern"].asText()).matcher(text).find())
    }

    @Bean fun mergeFindings(): NodeDefinition = PlatformNode(
        "logic.merge", "Объединить находки", NodeCategory.LOGIC,
        inputs = (1..8).map { PortSpec("findings$it", PortType.FINDINGS, false) },
        outputs = listOf(PortSpec("findings", PortType.FINDINGS)),
    ) { _, input ->
        result("findings", input.ports.toSortedMap().values.flatMap { findingsOf(json.valueToTree(it)) })
    }

    @Bean fun filterFindings(): NodeDefinition = findingsNode(
        "filter", "Фильтр находок", schema("""{"type":"object","properties":{"severity":{
        "enum":["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}},"required":["severity"],"additionalProperties":false}"""),
    ) { params, values -> values.filter { it.path("severity").asText() == params.path("severity").asText() } }

    @Bean fun filterFindingCategory(): NodeDefinition = findingsNode(
        "filter-category", "Фильтр по категории и классу", schema("""
            {"type":"object","properties":{"category":{"enum":["SECRET","SAST","SCA"]},
            "class":{"type":"string","minLength":1,"maxLength":100}},
            "required":["category"],"additionalProperties":false}
        """),
    ) { params, values ->
        val category = params.path("category").asText()
        val findingClass = params.path("class").textValue()
        values.filter { finding ->
            finding.path("category").asText() == category &&
                (findingClass == null || finding.path("class").asText() == findingClass)
        }
    }

    @Bean fun delayValue(): NodeDefinition = PlatformNode(
        "logic.delay", "Задержка", NodeCategory.LOGIC,
        inputs = listOf(PortSpec("value", PortType.ANY)),
        outputs = listOf(PortSpec("value", PortType.ANY)),
        paramsSchema = schema("""{"type":"object","properties":{"seconds":{"type":"integer","minimum":1,"maximum":10}},
            "required":["seconds"],"additionalProperties":false}"""),
    ) { ctx, input ->
        delay(ctx.params.path("seconds").asLong() * 1000)
        result("value", input.ports.getValue("value"))
    }

    @Bean fun deduplicateFindings(): NodeDefinition = findingsNode("deduplicate", "Удалить дубликаты") { _, values ->
        values.distinctBy { it.path("fingerprint").asText().ifEmpty { it.toString() } }
    }

    @Bean fun countFindings(): NodeDefinition = PlatformNode(
        "logic.count", "Подсчитать находки", NodeCategory.LOGIC,
        inputs = listOf(PortSpec("findings", PortType.FINDINGS)),
        outputs = listOf(PortSpec("count", PortType.ANY)),
    ) { _, input -> result("count", findingsOf(json.valueToTree(input.ports["findings"])).size) }

    private fun findingsNode(
        type: String,
        title: String,
        params: JsonNode = schema("""{"type":"object","additionalProperties":false}"""),
        action: (JsonNode, List<JsonNode>) -> List<JsonNode>,
    ) = PlatformNode("logic.$type", title, NodeCategory.LOGIC,
        listOf(PortSpec("findings", PortType.FINDINGS)), listOf(PortSpec("findings", PortType.FINDINGS)),
        params) { ctx, input ->
        result("findings", action(ctx.params, findingsOf(json.valueToTree(input.ports["findings"]))))
    }
}

fun findingsOf(value: JsonNode): List<JsonNode> {
    val findings = if (value.isArray) value else value.path("findings")
    return if (findings.isArray) findings.filter { it.isObject && it.hasNonNull("severity") } else emptyList()
}
