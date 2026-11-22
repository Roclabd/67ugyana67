package workflow.engine

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.TextNode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull
import java.nio.file.Path
import java.time.Instant
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.ConcurrentLinkedQueue

enum class RunStatus { RUNNING, SUCCESS, PARTIAL, FAILED }

enum class SkipReason { INACTIVE_BRANCH, MISSING_INPUT, UPSTREAM_FAILURE, RUN_STOPPED }

data class SkipCause(
    val reason: SkipReason,
    val nodeIds: List<String> = emptyList(),
    val edgeIds: List<String> = emptyList(),
)

data class NodeRun(
    val nodeId: String,
    val status: NodeStatus,
    val input: Map<String, Any?> = emptyMap(),
    val output: Map<String, Any?> = emptyMap(),
    val logs: List<String> = emptyList(),
    val durationMs: Long = 0,
    val error: String? = null,
    val coverage: JsonNode? = null,
    val startedAt: Instant? = null,
    val finishedAt: Instant? = null,
    val rulesVersion: String? = null,
    val skipCause: SkipCause? = null,
    val failureContextNodeIds: List<String>? = null,
)

data class RunEvent(val name: String, val data: Any, val node: NodeRun? = null)
data class Execution(val status: RunStatus, val nodeRuns: List<NodeRun>)

data class DeliveryFailure(val nodeId: String, val type: String, val error: String)

/**
 * Исход доставки уведомлений (ноды с notifyOnFailure). Не влияет на статус запуска и покрытие.
 * status: NONE - уведомления не выполнялись; DELIVERED - все дошли; PARTIAL - часть не дошла; FAILED - ни одно не дошло.
 */
data class Delivery(
    val status: String,
    val delivered: List<String> = emptyList(),
    val failed: List<DeliveryFailure> = emptyList(),
)

class Redaction(private val json: ObjectMapper, values: Collection<String>) {
    private val secrets = values.filter { it.isNotEmpty() }.distinct().sortedByDescending { it.length }
    private val privatePorts = Collections.synchronizedMap(IdentityHashMap<Any, PortType>())

    fun text(value: String): String = secrets.fold(value) { current, secret -> current.replace(secret, MASK) }

    fun tree(value: JsonNode, redactText: (String) -> String = ::text): JsonNode = when {
        value.isObject -> json.createObjectNode().also { result ->
            value.fields().forEach { (key, child) ->
                val safe = if (sensitiveKey.matches(key)) TextNode.valueOf(MASK) else tree(child, redactText)
                result.set<JsonNode>(redactText(key), safe)
            }
        }
        value.isArray -> json.createArrayNode().also { result -> value.forEach { result.add(tree(it, redactText)) } }
        value.isTextual -> TextNode.valueOf(redactText(value.textValue()))
        else -> value
    }

    fun ports(values: Map<String, Any?>, specs: List<PortSpec>): Map<String, Any?> = values.mapValues { (port, value) ->
        val declared = specs.firstOrNull { it.name == port }?.type
        if (value != null && declared in setOf(PortType.PROJECT_MODEL, PortType.WORKSPACE)) {
            privatePorts[value] = requireNotNull(declared)
        }
        val type = value?.let(privatePorts::get) ?: declared
        when {
            type == PortType.PROJECT_MODEL -> mapOf("kind" to "PROJECT_MODEL")
            type == PortType.WORKSPACE || value is Path -> "[workspace]"
            value == null -> null
            else -> tree(json.valueToTree(value))
        }
    }

    companion object {
        const val MASK = "••••"
        private val sensitiveKey = Regex("(?i)password|token|api[_-]?key|secret|authorization")
    }
}

class DagExecutor(
    private val registry: NodeRegistry,
    private val validator: GraphValidator,
    private val json: ObjectMapper,
) {
    private val expressions = Expressions(json)
    private val failureDeliveries = Semaphore(4)

    suspend fun execute(
        workflow: Workflow,
        runId: String,
        trigger: JsonNode,
        workDirectory: Path,
        redaction: Redaction,
        publish: (RunEvent) -> Unit,
    ): Execution {
        validator.requireValid(workflow)
        val incoming = workflow.edges.groupBy { it.to.node }
        val outputs = linkedMapOf<String, Map<String, Any?>>()
        val publicOutputs = linkedMapOf<String, Map<String, Any?>>()
        val nodeRuns = mutableListOf<NodeRun>()
        val notifications = workflow.nodes.filter { registry[it.type]?.notifyOnFailure == true }.sortedBy { it.id }
        val notificationIds = notifications.map { it.id }.toSet()
        val aiIds = workflow.nodes.filter { registry[it.type]?.category == NodeCategory.AI }.map { it.id }.toSet()
        val layers = workflow.layers().map { layer -> layer.filterNot { it.id in notificationIds } }
        val branchingNodes = workflow.nodes.filter { it.type in setOf("logic.if", "approval.wait") }
            .mapTo(mutableSetOf()) { it.id }
        val runsById = mutableMapOf<String, NodeRun>()
        val stopCauses = mutableListOf<String>()
        for (layer in layers + listOf(notifications)) {
            val analysis = lazy { analysisSnapshot(workflow, nodeRuns) }
            val analyzerCoverage = lazy { coverageByAnalyzer(workflow, nodeRuns) }
            val results = coroutineScope {
                layer.map { node ->
                    async {
                        val edges = incoming[node.id].orEmpty()
                        val active = edges.filter { outputs[it.from.node]?.containsKey(it.from.port) == true }
                        val ports = active.associate { it.to.port to outputs.getValue(it.from.node)[it.from.port] }
                        val definition = requireNotNull(registry[node.type])
                        val missing = definition.inputs.filter { it.required && !ports.containsKey(it.name) }
                            .mapTo(mutableSetOf()) { it.name }
                        val unavailable = when {
                            missing.isNotEmpty() -> edges.filter { it.to.port in missing }
                            active.isEmpty() -> edges
                            else -> emptyList()
                        }
                        val skipCause = skipCause(unavailable, runsById, stopCauses, branchingNodes,
                            missing.isNotEmpty() || (edges.isNotEmpty() && active.isEmpty()))
                        val result = if (skipCause != null) {
                            Result(NodeRun(node.id, NodeStatus.SKIPPED, finishedAt = Instant.now(), skipCause = skipCause))
                        } else runNode(node, definition, ports, publicOutputs, runId, trigger, workDirectory, redaction,
                            coverageStatus(workflow, nodeRuns), publish, workflowName = workflow.name,
                            analysis = analysis, analyzerCoverage = analyzerCoverage)
                        // Publish a completed node as soon as it finishes. Dependency resolution still waits for the layer.
                        if (result.run.status != NodeStatus.SKIPPED) {
                            publish(RunEvent("node.io", mapOf(
                                "nodeId" to node.id, "input" to result.run.input, "output" to result.run.output,
                            )))
                        }
                        publish(status(result.run))
                        result
                    }
                }.map { it.await() }
            }
            val wasStopped = stopCauses.isNotEmpty()
            for ((index, result) in results.withIndex()) {
                val run = result.run
                nodeRuns.add(run)
                runsById[run.nodeId] = run
                val keepGoing = layer[index].continueOnError
                // Сбой доставки уведомления не останавливает анализ.
                if (run.status == NodeStatus.FAILED && !keepGoing && !wasStopped && run.nodeId !in notificationIds) {
                    stopCauses.add(run.nodeId)
                }
                if (run.status != NodeStatus.FAILED || keepGoing) {
                    outputs[run.nodeId] = result.ports
                    publicOutputs[run.nodeId] = run.output
                }
            }
        }
        val result = when {
            stopCauses.isNotEmpty() -> RunStatus.FAILED
            // Объяснения AI необязательны: их неполнота не ухудшает итог анализа.
            nodeRuns.any { it.nodeId !in notificationIds && it.nodeId !in aiIds &&
                it.status in setOf(NodeStatus.PARTIAL, NodeStatus.FAILED) } ->
                RunStatus.PARTIAL
            else -> RunStatus.SUCCESS
        }
        return Execution(result, nodeRuns)
    }

    fun delivery(workflow: Workflow, runs: List<NodeRun>): Delivery {
        val types = workflow.nodes.filter { registry[it.type]?.notifyOnFailure == true }.associate { it.id to it.type }
        val attempted = runs.filter { it.nodeId in types && it.status != NodeStatus.SKIPPED }
        val failed = attempted.filter { it.status == NodeStatus.FAILED || it.status == NodeStatus.PARTIAL }
            .map { DeliveryFailure(it.nodeId, types.getValue(it.nodeId), it.error ?: "Доставка не выполнена.") }
        val failedIds = failed.map { it.nodeId }.toSet()
        val delivered = attempted.map { it.nodeId }.filter { it !in failedIds }
        return Delivery(when {
            attempted.isEmpty() -> "NONE"
            failed.isEmpty() -> "DELIVERED"
            delivered.isEmpty() -> "FAILED"
            else -> "PARTIAL"
        }, delivered, failed)
    }

    private fun skipCause(
        unavailable: List<WorkflowEdge>,
        runs: Map<String, NodeRun>,
        stopCauses: List<String>,
        branchingNodes: Set<String>,
        cannotRun: Boolean,
    ): SkipCause? {
        val blockedEdges = unavailable.mapNotNull { edge ->
            val source = runs[edge.from.node]
            val failed = when (source?.status) {
                NodeStatus.FAILED -> listOf(source.nodeId)
                NodeStatus.SKIPPED -> source.skipCause?.takeIf { it.reason == SkipReason.UPSTREAM_FAILURE }
                    ?.nodeIds.orEmpty()
                else -> emptyList()
            }
            failed.takeIf { it.isNotEmpty() }?.let { edge.id to it }
        }
        if (blockedEdges.isNotEmpty()) return SkipCause(
            SkipReason.UPSTREAM_FAILURE, blockedEdges.flatMap { it.second }.distinct(), blockedEdges.map { it.first },
        )
        if (unavailable.isNotEmpty() && unavailable.all { edge ->
                val source = runs[edge.from.node]
                source?.skipCause?.reason == SkipReason.INACTIVE_BRANCH ||
                    (edge.from.node in branchingNodes && source?.status == NodeStatus.SUCCESS &&
                        source.output.isNotEmpty())
            }
        ) return SkipCause(SkipReason.INACTIVE_BRANCH)
        if (stopCauses.isNotEmpty()) return SkipCause(SkipReason.RUN_STOPPED, stopCauses.toList())
        return if (cannotRun) SkipCause(SkipReason.MISSING_INPUT) else null
    }

    suspend fun notifyFailure(
        workflow: Workflow,
        runId: String,
        trigger: JsonNode,
        workDirectory: Path,
        redaction: Redaction,
        runs: List<NodeRun>,
        reason: String,
        publish: (RunEvent) -> Unit,
    ): List<NodeRun> {
        val known = runs.associateBy { it.nodeId }
        val nodes = workflow.nodes.associateBy { it.id }
        val outgoing = workflow.edges.groupBy { it.from.node }
        val roots = runs.filter { it.status != NodeStatus.SKIPPED }.map { it.nodeId }.ifEmpty {
            val type = "trigger." + trigger.path("kind").asText()
            val triggerNode = trigger.path("triggerNodeId").textValue()
            workflow.nodes.filter { it.type == type && (triggerNode == null || it.id == triggerNode) }.map { it.id }
        }
        val reachable = mutableSetOf<String>()
        val queue = ArrayDeque(roots)
        while (queue.isNotEmpty()) {
            val id = queue.removeFirst()
            if (!reachable.add(id)) continue
            val node = nodes[id] ?: continue
            val run = known[id]
            for (edge in outgoing[id].orEmpty()) {
                val active = when (run?.status) {
                    NodeStatus.SUCCESS, NodeStatus.PARTIAL -> run.output.containsKey(edge.from.port)
                    else -> node.type !in setOf("logic.if", "approval.wait")
                }
                if (active) queue.add(edge.to.node)
            }
        }
        val targets = workflow.nodes.filter {
            it.id in reachable && registry[it.type]?.notifyOnFailure == true &&
                (known[it.id] == null || known[it.id]?.status == NodeStatus.SKIPPED)
        }
        val previous = runs.associate { it.nodeId to it.output }
        val analyzerCoverage = lazy { coverageByAnalyzer(workflow, runs) }
        val failureContext = runs.filter { it.status == NodeStatus.FAILED }.map { it.nodeId }
        val delivered = coroutineScope {
            targets.map { node ->
                async {
                    val definition = requireNotNull(registry[node.type])
                    val result = failureDeliveries.withPermit {
                        withTimeoutOrNull(25_000) {
                            runNode(node, definition, emptyMap(), previous, runId, trigger, workDirectory,
                                redaction, "FAILED", publish, workflowName = workflow.name, failureReason = reason,
                                analyzerCoverage = analyzerCoverage).run
                        }
                    } ?: NodeRun(node.id, NodeStatus.FAILED, error = "Истекло время доставки уведомления.",
                        finishedAt = Instant.now())
                    val diagnostic = if (result.status == NodeStatus.FAILED) {
                        result.copy(failureContextNodeIds = failureContext.ifEmpty { null })
                    } else result
                    publish(status(diagnostic))
                    diagnostic
                }
            }.map { it.await() }
        }
        val updates = delivered.associateBy { it.nodeId }
        return runs.map { updates[it.nodeId] ?: it } + delivered.filter { it.nodeId !in known }
    }

    private suspend fun runNode(
        node: WorkflowNode,
        definition: NodeDefinition,
        ports: Map<String, Any?>,
        previous: Map<String, Map<String, Any?>>,
        runId: String,
        triggerData: JsonNode,
        workDirectory: Path,
        redaction: Redaction,
        coverageStatus: String,
        publish: (RunEvent) -> Unit,
        workflowName: String,
        failureReason: String? = null,
        analysis: Lazy<AnalysisSnapshot?> = lazyOf(null),
        analyzerCoverage: Lazy<Map<String, JsonNode>> = lazyOf(emptyMap()),
    ): Result {
        val started = Instant.now()
        val clock = System.nanoTime()
        publish(status(NodeRun(node.id, NodeStatus.RUNNING, startedAt = started)))
        val logs = ConcurrentLinkedQueue<String>()
        var safeInput = emptyMap<String, Any?>()
        var safeOutput = emptyMap<String, Any?>()
        var error: String? = null
        val output = try {
            safeInput = redaction.ports(ports, definition.inputs)
            val params = expressions.resolveParams(node.params, definition.secretParams, mapOf(
                "run" to json.createObjectNode().put("id", runId),
                "trigger" to triggerData,
                "findings" to json.valueToTree(aggregateFindings(safeInput)),
                "node" to json.valueToTree(previous.mapValues { mapOf("output" to it.value) }),
            ))
            require(validator.parameterErrors(node.type, params).isEmpty())
            val context = object : NodeContext {
                override val runId = runId
                override val workflowName = workflowName
                override val nodeId = node.id
                override val params = params
                override val workspace = ports.values.filterIsInstance<Path>().firstOrNull() ?: workDirectory
                override val trigger = triggerData
                override val coverageStatus = coverageStatus
                override val coverageByAnalyzer: Map<String, JsonNode> get() = analyzerCoverage.value
                override val failureReason = failureReason
                override val analysis: AnalysisSnapshot? get() = analysis.value
                override fun redact(message: String) = redaction.text(message)
                override fun log(message: String) {
                    if (logs.size >= 100) return
                    val safe = redaction.text(message).take(2000)
                    logs.add(safe)
                    publish(RunEvent("log", mapOf("nodeId" to nodeId, "message" to safe)))
                }
                override fun emitProgress(percent: Int, note: String?) {
                    publish(RunEvent("node.progress", mapOf(
                        "nodeId" to nodeId, "percent" to percent.coerceIn(0, 100),
                        "note" to note?.let { redaction.text(it).take(2000) },
                    )))
                }
            }
            runDetached { definition.run(context, NodeInput(ports)) }.also { result ->
                require(result.status in setOf(NodeStatus.SUCCESS, NodeStatus.PARTIAL, NodeStatus.FAILED, NodeStatus.SKIPPED))
                require(result.ports.keys.all { name -> definition.outputs.any { it.name == name } })
                safeOutput = redaction.ports(result.ports, definition.outputs)
            }
        } catch (exception: CancellationException) {
            throw exception
        } catch (failure: NodeFailure) {
            error = redaction.text(failure.message.orEmpty()).take(300)
            NodeOutput(emptyMap(), NodeStatus.FAILED)
        } catch (_: Throwable) {
            // Error (StackOverflowError, NoClassDefFoundError, OOM) тоже заканчивает ноду сбоем, а не убивает запуск молча.
            error = "Нода не завершила операцию. Проверьте вход и параметры."
            NodeOutput(emptyMap(), NodeStatus.FAILED)
        }
        val coverage = output.coverage?.let { redaction.tree(json.valueToTree(it)) }
        val status = if (definition.category == NodeCategory.ANALYZER && output.status == NodeStatus.SUCCESS &&
            coverage?.path("status")?.asText() != "COMPLETE"
        ) NodeStatus.PARTIAL else output.status
        val rulesVersion = output.rulesVersion ?: safeOutput.values.filterIsInstance<JsonNode>()
            .mapNotNull { it.path("rulesVersion").textValue() }.distinct().singleOrNull()
        val data = NodeRun(node.id, status, safeInput, safeOutput, logs.toList(),
            (System.nanoTime() - clock) / 1_000_000, error, coverage, started, Instant.now(),
            rulesVersion?.let(redaction::text))
        return Result(data, if (status == NodeStatus.SKIPPED) emptyMap() else output.ports)
    }

    fun analysisSnapshot(workflow: Workflow, runs: List<NodeRun>): AnalysisSnapshot? {
        val workflowId = workflow.id ?: return null
        val nodes = workflow.nodes.associateBy { it.id }
        val sourceKeys = runs.mapNotNull { run ->
            val source = nodes[run.nodeId] ?: return@mapNotNull null
            if (source.type !in setOf("source.repo", "source.archive")) return@mapNotNull null
            val revision = run.output["revision"] ?: return@mapNotNull null
            val tree = json.valueToTree<JsonNode>(revision)
            val scope = tree.path("subdir").asText()
            val commit = tree.path("commitSha").textValue()
            val repo = tree.path("repoUrl").textValue()
            if (commit != null && repo != null) "repo:$repo:$scope" to commit
            else tree.path("inputHash").textValue()?.let { "archive:$it:$scope" to it }
        }.distinct()
        val (sourceKey, inputHash) = sourceKeys.singleOrNull() ?: return null
        val versions = mutableSetOf<String>()
        val fingerprints = mutableSetOf<String>()
        for (run in runs) {
            val definition = nodes[run.nodeId]?.let { registry[it.type] } ?: continue
            if (definition.category != NodeCategory.ANALYZER || run.status == NodeStatus.SKIPPED) continue
            val ports = definition.outputs.filter { it.type in setOf(PortType.FINDINGS, PortType.REPORT) }
            if (ports.isEmpty()) continue
            if (run.status != NodeStatus.SUCCESS || run.coverage?.path("status")?.asText() != "COMPLETE") return null
            versions.add(run.rulesVersion?.takeIf { it.isNotBlank() } ?: return null)
            var sawResults = false
            for (port in ports) {
                val value = run.output[port.name] ?: continue
                val payload = json.valueToTree<JsonNode>(value)
                val findings = if (payload.isArray) payload else payload.path("findings")
                if (!findings.isArray) continue
                sawResults = true
                for (finding in findings) {
                    fingerprints.add(finding.path("fingerprint").textValue()?.takeIf { it.isNotBlank() } ?: return null)
                }
            }
            if (!sawResults) return null
        }
        if (versions.isEmpty()) return null
        return AnalysisSnapshot(workflowId, workflow.version, sourceKey, inputHash, versions, fingerprints)
    }

    private fun analyzerRuns(workflow: Workflow, runs: List<NodeRun>): List<NodeRun> {
        val analyzerIds = workflow.nodes.filter { registry[it.type]?.category == NodeCategory.ANALYZER }.map { it.id }.toSet()
        return runs.filter { it.nodeId in analyzerIds && it.status != NodeStatus.SKIPPED }
    }

    private fun coverageByAnalyzer(workflow: Workflow, runs: List<NodeRun>): Map<String, JsonNode> =
        analyzerRuns(workflow, runs).mapNotNull { run -> run.coverage?.let { run.nodeId to it } }.toMap()

    fun coverageStatus(workflow: Workflow, runs: List<NodeRun>): String {
        val scans = analyzerRuns(workflow, runs)
        return when {
            scans.any { it.status == NodeStatus.FAILED || it.coverage?.path("status")?.asText() == "FAILED" } -> "FAILED"
            scans.isEmpty() || scans.any { it.status != NodeStatus.SUCCESS ||
                it.coverage?.path("status")?.asText() != "COMPLETE" } -> "PARTIAL"
            else -> "COMPLETE"
        }
    }

    private val nodeScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Нода исполняется в отдельной корутине, а вызывающий ждёт отменяемо: бюджет запуска прерывает ожидание,
     * даже если сама нода застряла в блокирующем коде.
     */
    private suspend fun <T> runDetached(block: suspend () -> T): T {
        val job = nodeScope.async { block() }
        try {
            return job.await()
        } catch (cancelled: CancellationException) {
            job.cancel()
            throw cancelled
        }
    }

    private fun aggregateFindings(ports: Map<String, Any?>): Map<String, Any> {
        val found = ports.values.flatMap { value ->
            if (value == null || value is Path) return@flatMap emptyList()
            val tree = json.valueToTree<JsonNode>(value)
            val findings = if (tree.isArray) tree else tree.path("findings")
            findings.filter { it.isObject && it.has("severity") }
        }
        return mapOf("count" to found.size, "bySeverity" to listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            .associateWith { severity -> found.count { it.path("severity").asText() == severity } })
    }

    private fun status(run: NodeRun) = RunEvent("node.status", mapOf(
        "nodeId" to run.nodeId, "status" to run.status, "startedAt" to run.startedAt,
        "finishedAt" to run.finishedAt, "error" to run.error, "coverage" to run.coverage,
        "skipCause" to run.skipCause, "failureContextNodeIds" to run.failureContextNodeIds,
    ), node = run)

    private data class Result(val run: NodeRun, val ports: Map<String, Any?> = emptyMap())
}
