package workflow.ai

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import ru.codeguard.ai.llm.AiLog
import ru.codeguard.ai.llm.ChatMessage
import ru.codeguard.ai.llm.Checked
import ru.codeguard.ai.llm.JsonCompletion
import ru.codeguard.ai.llm.LlmClient
import ru.codeguard.ai.llm.ResponseCache
import workflow.engine.Endpoint
import workflow.engine.Position
import workflow.engine.Workflow
import workflow.engine.WorkflowEdge
import workflow.engine.WorkflowGenerator
import workflow.engine.WorkflowNode

/**
 * Генерация сценария из текста (звёздочка 3). Каталог нод и запрос пользователя собирает сервер (TemplatesController),
 * здесь — только обращение к модели и разбор ответа в Workflow.
 *
 * Два уровня проверки:
 *  1. здесь — структура JSON (ноды, связи, ссылки связей на существующие ноды); ошибка → повтор с её текстом;
 *  2. на сервере — GraphValidator по реестру: известные типы, совместимые порты, параметры по схеме, циклы, секреты.
 * Граф, не прошедший сервер, не сохраняется и не запускается (инвариант 5.8).
 */
class LlmWorkflowGenerator(
    private val client: LlmClient,
    private val cache: ResponseCache? = null,
    private val log: AiLog = AiLog.NONE,
) : WorkflowGenerator {

    override suspend fun generate(instructions: String): Workflow = runInterruptible(Dispatchers.IO) {
        val outcome = JsonCompletion(client, cache, log).complete("generate", PROMPT_VERSION, messages(instructions), ::parse)
        outcome.value ?: throw GenerationFailed(outcome.error ?: "Модель не вернула сценарий")
    }

    class GenerationFailed(message: String) : RuntimeException(message)

    companion object {
        const val PROMPT_VERSION = "generate-1"
        private const val MAX_NODES = 30

        private val SYSTEM = """
            Ты собираешь сценарий проверки безопасности для визуального конструктора из нод.
            Отвечай ТОЛЬКО JSON-объектом без markdown и пояснений:
            {"name": "…", "nodes": [{"id": "…", "type": "…", "params": {…}, "position": {"x": 0, "y": 0}}],
             "edges": [{"id": "…", "from": {"node": "<id>", "port": "<выход>"}, "to": {"node": "<id>", "port": "<вход>"}}]}
            Используй только типы нод, порты и параметры из каталога в запросе. Связь соединяет выход одной ноды с входом другой.
            Располагай ноды слева направо по порядку выполнения, шаг по x — 260.
        """.trimIndent()

        fun messages(instructions: String) = listOf(ChatMessage("system", SYSTEM), ChatMessage("user", instructions))

        /** Структурная проверка ответа модели. Ошибки уходят модели в повторном запросе. */
        fun parse(root: JsonNode): Checked<Workflow> {
            val errors = mutableListOf<String>()
            val name = root.path("name").asText("").trim().ifEmpty { "Сценарий из текста" }.take(120)
            val rawNodes = root.path("nodes")
            if (!rawNodes.isArray || rawNodes.isEmpty) return Checked.Invalid(listOf("nodes — непустой массив нод"))
            if (rawNodes.size() > MAX_NODES) errors += "Слишком много нод: ${rawNodes.size()}, допустимо до $MAX_NODES"

            val nodes = rawNodes.mapIndexedNotNull { i, n ->
                val id = n.path("id").asText("").trim()
                val type = n.path("type").asText("").trim()
                if (id.isEmpty() || type.isEmpty()) {
                    errors += "nodes[$i]: нужны строковые id и type"
                    return@mapIndexedNotNull null
                }
                val params = n.get("params")?.takeIf { it.isObject } ?: JsonNodeFactory.instance.objectNode()
                val p = n.path("position")
                WorkflowNode(id, type, params, Position(p.path("x").asDouble(i * 260.0), p.path("y").asDouble(0.0)))
            }
            nodes.groupBy { it.id }.filter { it.value.size > 1 }.keys.forEach { errors += "Повторяется id ноды «$it»" }

            val ids = nodes.map { it.id }.toSet()
            val edges = root.path("edges").takeIf { it.isArray }?.mapIndexedNotNull { i, e ->
                val from = endpoint(e.path("from"))
                val to = endpoint(e.path("to"))
                if (from == null || to == null) {
                    errors += "edges[$i]: нужны from и to вида {node, port}"
                    return@mapIndexedNotNull null
                }
                listOf(from, to).filter { it.node !in ids }.forEach { errors += "edges[$i]: нет ноды «${it.node}»" }
                val id = e.path("id").asText("").trim().ifEmpty { "${from.node}_${from.port}_${to.node}_${to.port}" }
                WorkflowEdge(id, from, to)
            }.orEmpty()
            edges.groupBy { it.id }.filter { it.value.size > 1 }.keys.forEach { errors += "Повторяется id связи «$it»" }

            return if (errors.isEmpty()) Checked.Ok(Workflow(name = name, nodes = nodes, edges = edges)) else Checked.Invalid(errors)
        }

        private fun endpoint(n: JsonNode): Endpoint? {
            val node = n.path("node").asText("").trim()
            val port = n.path("port").asText("").trim()
            return if (node.isEmpty() || port.isEmpty()) null else Endpoint(node, port)
        }
    }
}
