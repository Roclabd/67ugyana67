package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.springframework.beans.factory.ObjectProvider
import org.springframework.stereotype.Service
import workflow.engine.*
import workflow.nodes.findingsOf

@Service
class ReportService(
    private val json: ObjectMapper,
    private val registry: NodeRegistry,
    private val exporters: ObjectProvider<ReportExporter>,
) {
    fun scans(workflow: Workflow, runs: List<NodeRun>): List<NodeRun> {
        val ids = workflow.nodes.filter { node ->
            registry[node.type]?.let { it.category == NodeCategory.ANALYZER && it.resultPorts().isNotEmpty() } == true
        }.map { it.id }.toSet()
        return runs.filter { it.nodeId in ids && it.status != NodeStatus.SKIPPED }
    }

    fun scanOutputs(workflow: Workflow, scan: NodeRun): List<JsonNode> {
        val node = workflow.nodes.first { it.id == scan.nodeId }
        val ports = registry[node.type]?.resultPorts().orEmpty()
        return ports.mapNotNull { port -> scan.output[port.name] as? JsonNode }
    }

    private fun NodeDefinition.resultPorts() = outputs.filter { it.type in setOf(PortType.REPORT, PortType.FINDINGS) }

    fun make(
        run: RunRecord,
        workflow: Workflow,
        nodeRuns: List<NodeRun>,
        coverage: String,
        inputHash: String?,
        sourceSubdir: String? = null,
    ): JsonNode? {
        val scans = scans(workflow, nodeRuns)
        val quality = qualityBlock(workflow, nodeRuns)
        if (scans.isEmpty() && quality == null) return null
        val aiNodeIds = workflow.nodes.filter { registry[it.type]?.category == NodeCategory.AI }
            .map { it.id }.toSet()
        val aiRuns = nodeRuns.filter { it.nodeId in aiNodeIds }
        val ai = aiRuns.asReversed().firstNotNullOfOrNull { nodeRun ->
            (nodeRun.output["explanation"] as? JsonNode)?.get("ai")?.takeIf { it.isObject }
        }
        val reportNodeIds = workflow.nodes.filter { it.type == "output.report" }.map { it.id }.toSet()
        val enriched = nodeRuns.asReversed().firstNotNullOfOrNull { run ->
            if (run.nodeId in reportNodeIds) {
                (run.output["report"] as? JsonNode)?.takeIf { it.path("ai").isObject }
            } else null
        }
        val explained = enriched?.let(::findingsOf).orEmpty() + aiRuns.flatMap { nodeRun ->
            (nodeRun.output["findings"] as? JsonNode)?.let(::findingsOf).orEmpty()
        }
        val annotations = explained.mapNotNull { finding ->
            val explanation = finding.path("ai").takeIf { it.isObject } ?: return@mapNotNull null
            finding.fingerprint()?.let { it to explanation }
        }.toMap()
        val findings = scans.flatMap { scan -> scanOutputs(workflow, scan).flatMap(::findingsOf) }
            .distinctBy { it.path("fingerprint").asText().ifEmpty { it.toString() } }
            .sortedWith(compareBy<JsonNode>({ categoryOrder.indexOf(it.path("category").asText()) },
                { it.path("path").asText() }, { it.path("line").asInt() },
                { it.path("class").asText(it.path("advisoryId").asText()) }))
            .map { finding ->
                val explanation = annotations[finding.fingerprint()]
                if (explanation != null && finding is ObjectNode) {
                    finding.deepCopy().set<JsonNode>("ai", explanation)
                } else finding
            }
        return json.valueToTree<ObjectNode>(mapOf(
            "runId" to run.id,
            "workflowId" to run.workflowId,
            "workflowVersion" to run.workflowVersion,
            "inputHash" to (inputHash ?: scans.mapNotNull { scan ->
                scanOutputs(workflow, scan).firstNotNullOfOrNull { it.path("inputHash").textValue() }
            }.distinct().singleOrNull()),
            "rulesVersion" to rulesVersionSignature(scans.mapNotNull { it.rulesVersion }),
            "coverage" to mapOf("status" to coverage, "byAnalyzer" to scans.associate {
                it.nodeId to (it.coverage ?: json.createObjectNode().put("status", "FAILED"))
            }, "analyzerTypes" to scans.associate { scan ->
                scan.nodeId to workflow.nodes.first { it.id == scan.nodeId }.type
            }),
            "findings" to findings,
            "ai" to (ai ?: enriched?.get("ai") ?: json.createObjectNode().put("status", "NOT_RECEIVED")),
        )).apply {
            sourceSubdir?.let { put("sourceSubdir", it) }
            // «Языки проекта»: сколько файлов на каком языке и что из этого анализировалось.
            val parseIds = workflow.nodes.filter { it.type == "analyzer.parse" }.map { it.id }.toSet()
            nodeRuns.firstOrNull { it.nodeId in parseIds && it.coverage?.path("languages")?.isArray == true }
                ?.coverage?.let { parsed ->
                    val languages = json.createArrayNode()
                    for (language in parsed.path("languages")) {
                        val supported = language.path("sastSupported").asBoolean()
                        languages.addObject().put("name", language.path("name").asText())
                            .put("files", language.path("files").asInt())
                            .put("secret", true).put("sca", supported).put("sast", supported)
                            .put("note", if (supported) "анализируется (SECRET, SCA, SAST)"
                            else if (language.path("script").asBoolean()) "SECRET: да; SAST не применим (скрипты)"
                            else "SECRET: да; SAST и SCA: не поддерживается")
                    }
                    set<JsonNode>("languages", languages)
                    val ignored = parsed.path("ignoredDirectories")
                    if (ignored.isArray && ignored.size() > 0) set<JsonNode>("ignoredDirectories", ignored)
                }
            // Блок качества необязателен и версионируется; без ноды качества отчёт не меняется.
            quality?.let { set<JsonNode>("quality", it) }
        }
    }

    /** Результат ноды `analyzer.quality`: не находка безопасности и не часть покрытия, поэтому живёт отдельным блоком. */
    private fun qualityBlock(workflow: Workflow, runs: List<NodeRun>): JsonNode? {
        val ids = workflow.nodes.filter { it.type == QUALITY_NODE }.map { it.id }.toSet()
        if (ids.isEmpty()) return null
        return runs.filter { it.nodeId in ids && it.status != NodeStatus.SKIPPED }
            .firstNotNullOfOrNull { (it.output["quality"] as? JsonNode)?.takeIf(JsonNode::isObject) }
    }

    private fun JsonNode.fingerprint(): String? = path("fingerprint").textValue()?.takeIf { it.isNotBlank() }

    fun organizer(report: JsonNode): JsonNode {
        exporters.ifAvailable?.let { return it.json(report) }
        val findings = json.createArrayNode()
        for (item in findingsOf(report)) {
            val category = item.path("category").asText()
            val keys = when (category) {
                "SECRET", "SAST" -> listOf("category", "path", "class", "line", "endLine", "severity", "description", "remediation")
                "SCA" -> listOf("category", "path", "group", "artifact", "version", "advisoryId", "severity", "description", "remediation")
                else -> continue
            }
            val finding = json.createObjectNode()
            keys.filter(item::hasNonNull).forEach { field -> finding.set<JsonNode>(field, item[field]) }
            if (finding.path("line") == finding.path("endLine")) finding.remove("endLine")
            findings.add(finding)
        }
        return json.createObjectNode().set("findings", findings)
    }

    fun sarif(report: JsonNode): JsonNode = exporters.ifAvailable?.sarif(report) ?: throw MissingResource()

    fun pdf(report: JsonNode, meta: JsonNode?): ByteArray =
        exporters.ifAvailable?.pdf(report, meta) ?: throw MissingResource()

    fun markdown(report: JsonNode): String = exporters.ifAvailable?.markdown(report) ?: buildString {
        val coverage = report.path("coverage").path("status").asText()
        val findings = findingsOf(report)
        appendLine("# Отчёт проверки")
        appendLine()
        appendLine("Покрытие: $coverage")
        if (coverage != "COMPLETE") appendLine("Проверка завершена частично или с ошибкой. Итог неизвестен.")
        if (coverage == "COMPLETE" || findings.isNotEmpty()) appendLine("Найдено: ${findings.size}")
        for (finding in findings) {
            appendLine()
            appendLine("- ${finding.path("severity").asText()} · ${finding.path("path").asText()} · ${finding.path("title").asText()}")
        }
    }

    companion object {
        const val QUALITY_NODE = "analyzer.quality"
        val severities = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        private val categoryOrder = listOf("SECRET", "SAST", "SCA")
    }
}
