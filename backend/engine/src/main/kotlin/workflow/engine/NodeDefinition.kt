package workflow.engine

import com.fasterxml.jackson.databind.JsonNode
import java.nio.file.Path

interface NodeDefinition {
    val type: String
    val title: String
    val description: String? get() = null
    val category: NodeCategory
    val inputs: List<PortSpec>
    val outputs: List<PortSpec>
    val paramsSchema: JsonNode
    val secretParams: Set<String> get() = emptySet()
    val notifyOnFailure: Boolean get() = false
    fun validateParams(params: JsonNode): Boolean = true
    suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput
}

enum class NodeCategory { TRIGGER, SOURCE, ANALYZER, LOGIC, AI, OUTPUT }
enum class PortType { WORKSPACE, PROJECT_MODEL, FINDINGS, REPORT, DECISION, ANY }
data class PortSpec(val name: String, val type: PortType, val required: Boolean = true)

interface NodeContext {
    val runId: String
    val workflowName: String? get() = null
    val nodeId: String
    val params: JsonNode
    val workspace: Path?
    val trigger: JsonNode
    val coverageStatus: String
    val coverageByAnalyzer: Map<String, JsonNode> get() = emptyMap()
    val failureReason: String? get() = null
    val analysis: AnalysisSnapshot? get() = null
    fun redact(message: String): String
    fun log(message: String)
    fun emitProgress(percent: Int, note: String? = null)
}

data class AnalysisSnapshot(
    val workflowId: String,
    val workflowVersion: Long,
    val sourceKey: String,
    val inputHash: String,
    val rulesVersions: Set<String>,
    val fingerprints: Set<String>,
)

data class NodeInput(val ports: Map<String, Any?>)
data class NodeOutput(
    val ports: Map<String, Any?>,
    val status: NodeStatus = NodeStatus.SUCCESS,
    val coverage: Any? = null,
    val rulesVersion: String? = null,
)

enum class NodeStatus { PENDING, RUNNING, SUCCESS, PARTIAL, FAILED, SKIPPED }

class NodeFailure(message: String) : RuntimeException(message)

// Optional integration beans supplied by the analyzer and AI modules.
interface ReportExporter {
    fun json(report: JsonNode): JsonNode
    fun markdown(report: JsonNode): String
    fun sarif(report: JsonNode): JsonNode? = null

    /** PDF-отчёт; `meta` — необязательные поля запуска (workflowName, finishedAt, source, commit). null — PDF не поддерживается. */
    fun pdf(report: JsonNode, meta: JsonNode? = null): ByteArray? = null
}

interface WorkflowGenerator {
    suspend fun generate(instructions: String): Workflow
}

interface ValidatedExplanation {
    val text: String
}

class NodeRegistry(definitions: List<NodeDefinition>) {
    val nodes = definitions.sortedBy { it.type }
    private val byType = nodes.associateBy { it.type }

    init {
        require(nodes.size == byType.size) { "Duplicate node type" }
        for (node in nodes) {
            require(node.inputs.map { it.name }.distinct().size == node.inputs.size)
            require(node.outputs.map { it.name }.distinct().size == node.outputs.size)
        }
    }

    operator fun get(type: String): NodeDefinition? = byType[type]
}
