package workflow.quality

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Component
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import workflow.engine.ruCount
import java.nio.file.Path

/**
 * Нода «Проверка качества кода». Не анализатор безопасности: категория OUTPUT и выход типа ANY, чтобы сбор находок,
 * покрытие безопасности, снимок для «только новых» и CI-гейт её не видели. Статус ноды всегда SUCCESS:
 * результат проверки (замечания, тайм-аут, пропуски) — в данных `quality`, а не в статусе запуска.
 */
@Component
class QualityNode(checkers: List<LanguageChecker>) : NodeDefinition {
    private val engine = QualityEngine(checkers)

    override val type = "analyzer.quality"
    override val title = "Проверка качества кода"
    override val description = "Kotlin, Python, JavaScript: синтаксис, несовместимые типы, неразрешённые ссылки, функциональные дефекты. Безопасность не затрагивает."
    override val category = NodeCategory.OUTPUT
    override val inputs = listOf(PortSpec("workspace", PortType.WORKSPACE))
    override val outputs = listOf(PortSpec("quality", PortType.ANY))
    override val paramsSchema: JsonNode = JsonNodeFactory.instance.objectNode().apply {
        put("type", "object")
        put("additionalProperties", false)
        val properties = putObject("properties")
        properties.putObject("kinds").apply {
            put("type", "array"); put("title", "Виды диагностики"); put("uniqueItems", true)
            putObject("items").put("type", "string").putArray("enum").apply { DiagnosticKind.entries.forEach { add(it.code) } }
            putArray("default").apply { DiagnosticKind.entries.forEach { add(it.code) } }
        }
        properties.putObject("languages").apply {
            put("type", "array"); put("title", "Языки"); put("uniqueItems", true)
            putObject("items").put("type", "string").putArray("enum").apply { engine.languages.forEach { add(it) } }
            putArray("default").apply { engine.languages.forEach { add(it) } }
        }
        properties.putObject("timeoutSeconds").put("type", "integer").put("title", "Тайм-аут, секунд")
            .put("minimum", 1).put("maximum", 90).put("default", 30)
    }

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.Default) {
        val workspace = input.ports["workspace"] as? Path
            ?: return@withContext NodeOutput(mapOf("quality" to payload(errorReport("На вход не пришла рабочая папка."))))
        val kinds = ctx.params.path("kinds").takeIf { it.isArray }?.mapNotNull { n -> DiagnosticKind.entries.firstOrNull { it.code == n.asText() } }?.toSet()
            ?.takeIf { it.isNotEmpty() } ?: DiagnosticKind.entries.toSet()
        val languages = ctx.params.path("languages").takeIf { it.isArray }?.map { it.asText() }?.toSet()?.takeIf { it.isNotEmpty() }
        val seconds = ctx.params.path("timeoutSeconds").asLong(30).coerceIn(1, 90)
        val report = try {
            engine.run(workspace, QualityOptions(kinds, languages, seconds * 1000))
        } catch (_: Exception) {
            errorReport("Проверка качества не завершилась из-за внутренней ошибки.")
        }
        ctx.log("Качество кода: ${report.status}, ${ruCount(report.diagnostics.size, "замечание", "замечания", "замечаний")}, ${ruCount(report.filesAnalyzed, "файл", "файла", "файлов")}")
        NodeOutput(mapOf("quality" to payload(report)))
    }

    private fun errorReport(message: String) = QualityReport(QualityStatus.ERROR, emptyList(), false, 0, emptyMap(), emptyList(), emptyList(),
        engine.rules, 0, message)

    companion object {
        const val VERSION = 1

        /** Версионируемый блок `quality` для ответа запуска и отчёта. */
        fun payload(r: QualityReport): Map<String, Any?> = linkedMapOf(
            "version" to VERSION,
            "status" to r.status.name,
            "message" to r.message,
            "durationMs" to r.durationMs,
            "filesAnalyzed" to r.filesAnalyzed,
            "filesByLanguage" to r.filesByLanguage,
            "truncated" to r.truncated,
            "summary" to linkedMapOf(
                "total" to r.diagnostics.size,
                "byKind" to DiagnosticKind.entries.associate { k -> k.code to r.diagnostics.count { it.kind == k } },
                "byLanguage" to r.diagnostics.groupingBy { it.language }.eachCount().toSortedMap(),
            ),
            "diagnostics" to r.diagnostics.map { d ->
                linkedMapOf("kind" to d.kind.code, "rule" to d.rule, "language" to d.language, "path" to d.path, "line" to d.line,
                    "column" to d.column, "message" to d.message, "confidence" to d.confidence.name)
            },
            "skipped" to r.skipped.map { mapOf("path" to it.path, "reason" to it.reason) },
            "unsupported" to r.unsupported,
            "rules" to r.rules.map { mapOf("id" to it.id, "kind" to it.kind.code, "language" to it.language, "title" to it.title) },
        )
    }
}
