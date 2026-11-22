package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.annotation.PreDestroy
import kotlinx.coroutines.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Service
import workflow.engine.*
import workflow.nodes.InputRejected
import workflow.nodes.SourceNodes
import workflow.nodes.deleteTree
import workflow.nodes.findingsOf
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore

@Service
class RunService(
    private val json: ObjectMapper,
    private val workflows: WorkflowStore,
    private val history: RunStore,
    private val executor: DagExecutor,
    private val validator: GraphValidator,
    private val reports: ReportService,
    private val sources: SourceNodes,
    private val decisions: ReviewDecisions,
    private val patches: PatchService,
    private val telegram: TelegramSettingsStore,
    private val demo: DemoMode,
    @Value("\${workflow.data-dir:data}") private val data: String,
    @Value("\${TELEGRAM_BOT_TOKEN:}") private val telegramToken: String,
    @Value("\${SMTP_PASSWORD:}") private val smtpPassword: String,
    @Value("\${CI_TOKEN:}") private val ciToken: String,
    @Value("\${LLM_API_KEY:}") private val llmKey: String,
    @Value("\${RUN_TIMEOUT_SECONDS:240}") private val aiRunTimeoutSeconds: Long = AI_RUN_SECONDS,
    /** Только для тестов: если больше нуля, заменяет бюджет запуска (мс). */
    @Value("\${workflow.run-budget-millis:0}") private val budgetOverrideMillis: Long = 0,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val slots = Semaphore(4)
    private val secrets = listOf(telegramToken, smtpPassword, ciToken, llmKey)

    private fun redactionSecrets(): List<String> =
        secrets + listOfNotNull(runCatching { telegram.defaults().token }.getOrNull())

    @EventListener(ApplicationReadyEvent::class)
    fun recoverInterruptedRuns() {
        for (run in history.running()) history.finish(run.copy(
            status = RunStatus.FAILED, coverageStatus = "FAILED", finishedAt = Instant.now(),
            error = run.error ?: "Запуск прерван перезапуском сервера.",
        ))
    }

    @PreDestroy
    fun shutDown() { scope.cancel() }

    fun start(id: String, trigger: JsonNode, triggerNode: String? = null): RunTicket =
        start(workflows.unlocked(id), trigger, triggerNode)

    fun startScheduled(snapshot: Workflow, trigger: JsonNode, triggerNode: String) {
        var workflow: Workflow? = null
        try {
            workflow = workflows.unlocked(requireNotNull(snapshot.id))
            start(workflow, trigger, triggerNode)
        } catch (failure: RuntimeException) {
            val target = workflow ?: snapshot
            val redaction = Redaction(json, (workflow?.let(workflows::secretValues)).orEmpty() + redactionSecrets())
            val reason = redaction.text(when (failure) {
                is InvalidGraph -> "Сохранённый граф не прошёл проверку."
                is MissingResource -> "Сценарий недоступен."
                is Conflict -> failure.message ?: "Запуск сейчас недоступен."
                is InputRejected -> failure.message ?: "Источник не прошёл проверку."
                else -> "Не удалось подготовить запуск по расписанию."
            }).take(300)
            val id = UUID.randomUUID().toString()
            val data = trigger.deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>().put("triggerNodeId", triggerNode)
            val record = RunRecord(id, requireNotNull(target.id), target.version, redaction.tree(data),
                RunStatus.RUNNING, Instant.now(), workflowName = redaction.text(target.name), error = reason)
            history.begin(record)
            val canNotify = workflow != null
            scope.launch {
                var deliveries = emptyList<NodeRun>()
                try {
                    if (canNotify) {
                        deliveries = executor.notifyFailure(target, id, data, Path.of(this@RunService.data), redaction,
                            emptyList(), reason) { history.event(id, it) }
                    }
                } finally {
                    withContext(NonCancellable + Dispatchers.IO) {
                        history.finish(record.copy(status = RunStatus.FAILED, coverageStatus = "FAILED",
                            finishedAt = Instant.now(), nodeRuns = deliveries,
                            delivery = if (canNotify) executor.delivery(target, deliveries) else null))
                    }
                }
            }
        }
    }

    private fun start(original: Workflow, trigger: JsonNode, triggerNode: String?): RunTicket {
        validator.requireValid(original)
        val workflow = demo.sanitize(original)
        validator.requireValid(workflow)
        val triggerType = "trigger." + trigger.path("kind").asText()
        if (workflow.nodes.none { it.type == triggerType && (triggerNode == null || it.id == triggerNode) }) {
            throw InputRejected("В сценарии отсутствует триггер ${trigger.path("kind").asText()}")
        }
        val source = trigger.path("source")
        if (!source.isMissingNode) {
            when (source.path("kind").asText()) {
                "repo" -> sources.validateRepository(source.path("url").asText())
                "upload" -> {
                    val uploadId = source.path("uploadId").asText()
                    if (!uuid.matches(uploadId)) {
                        throw InputRejected("Укажите корректный uploadId.")
                    }
                }
                else -> throw InputRejected("Укажите тип источника upload или repo")
            }
        }
        if (!slots.tryAcquire()) throw Conflict("Все четыре слота выполнения заняты")
        try {
            val id = UUID.randomUUID().toString()
            val redaction = Redaction(json, workflows.secretValues(workflow) + redactionSecrets())
            val record = RunRecord(id, requireNotNull(workflow.id), workflow.version, redaction.tree(trigger),
                RunStatus.RUNNING, Instant.now(), workflowName = redaction.text(workflow.name))
            history.begin(record)
            val task = scope.async { execute(workflow, record, trigger, triggerNode, redaction) }
            task.invokeOnCompletion { slots.release() }
            return RunTicket(id, task)
        } catch (error: Exception) {
            slots.release()
            throw error
        }
    }

    private suspend fun execute(
        workflow: Workflow,
        record: RunRecord,
        trigger: JsonNode,
        triggerNode: String?,
        redaction: Redaction,
    ): RunRecord {
        var workDirectory: Path? = null
        val runtimeTrigger = trigger.deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>()
        if (triggerNode != null) runtimeTrigger.put("triggerNodeId", triggerNode)
        val observed = ConcurrentHashMap<String, NodeRun>()
        val publish: (RunEvent) -> Unit = { event ->
            event.node?.let { observed[it.nodeId] = it }
            history.event(record.id, event)
        }
        suspend fun onInterrupted(reason: String): RunRecord {
            val interrupted = workflow.nodes.mapNotNull { node ->
                observed[node.id]?.let { state ->
                    if (state.status != NodeStatus.RUNNING) state
                    else state.copy(status = NodeStatus.FAILED, error = reason, finishedAt = Instant.now())
                }
            }
            val results = if (currentCoroutineContext().isActive) {
                runCatching {
                    executor.notifyFailure(workflow, record.id, runtimeTrigger, workDirectory ?: Path.of(data),
                        redaction, interrupted, reason, publish)
                }.getOrDefault(interrupted)
            } else interrupted
            return record.copy(status = RunStatus.FAILED, finishedAt = Instant.now(), coverageStatus = "FAILED",
                nodeRuns = results, error = reason, delivery = executor.delivery(workflow, results))
        }
        val final = try {
            val directory = Path.of(data).toAbsolutePath().resolve("runs/${record.id}")
            workDirectory = withContext(Dispatchers.IO) { Files.createDirectories(directory) }
            val reviewBudget = workflow.nodes.filter { it.type == REVIEW_WAIT_NODE }
                .sumOf { reviewWaitSeconds(it.params) }.coerceAtMost(600L)
            val hasAi = workflow.nodes.any { it.type.startsWith("ai.") }
            val budget = if (budgetOverrideMillis > 0) budgetOverrideMillis
            else runBudgetMillis(hasAi, aiRunTimeoutSeconds, reviewBudget)
            val execution = withTimeout(budget) {
                executor.execute(workflow, record.id, runtimeTrigger, workDirectory, redaction, publish)
            }
            val reason = if (execution.status == RunStatus.FAILED) {
                val continuing = workflow.nodes.filter { it.continueOnError }.map { it.id }.toSet()
                execution.nodeRuns.firstOrNull { it.status == NodeStatus.FAILED && it.nodeId !in continuing }?.error
                    ?: "Одна из нод завершилась с ошибкой."
            } else null
            val nodeRuns = if (reason != null) {
                executor.notifyFailure(workflow, record.id, runtimeTrigger, workDirectory, redaction, execution.nodeRuns,
                    reason, publish)
            } else execution.nodeRuns
            val scans = reports.scans(workflow, execution.nodeRuns)
            val validPayloads = scans.all { scan ->
                reports.scanOutputs(workflow, scan).any { payload ->
                    val findings = if (payload.isArray) payload else payload.path("findings")
                    findings.isArray && findings.all { it.path("severity").asText() in ReportService.severities }
                }
            }
            val coverage = when {
                execution.status == RunStatus.FAILED -> "FAILED"
                !validPayloads -> "PARTIAL"
                else -> executor.coverageStatus(workflow, execution.nodeRuns)
            }
            val revision = sourceRevision(workflow, execution.nodeRuns, scans)
            val hash = revision?.path("commitSha")?.textValue() ?: revision?.path("inputHash")?.textValue()
            val requestedSha = trigger.path("commitSha").textValue()
            val verified = requestedSha != null && revision?.path("commitSha")?.textValue() == requestedSha &&
                revision.path("repoUrl").textValue() == trigger.path("source").path("url").textValue() &&
                scans.none { scan -> reports.scanOutputs(workflow, scan).any { payload ->
                    payload.hasNonNull("inputHash") && payload.path("inputHash").asText() != requestedSha
                } }
            val sourceSubdir = revision?.takeIf { it.hasNonNull("commitSha") }
                ?.path("subdir")?.textValue()?.takeIf(String::isNotEmpty)
            val report = reports.make(record, workflow, execution.nodeRuns, coverage, hash, sourceSubdir)
            val findings = report?.let(::findingsOf).orEmpty()
            if (report != null && findings.isNotEmpty()) {
                // Патчи нужны только для просмотра: сбой построения не должен ронять запуск.
                runCatching { patches.capture(record.id, report, snapshotProject(workflow, execution.nodeRuns, directory)) }
            }
            val counts = if (coverage == "COMPLETE" || findings.isNotEmpty()) {
                ReportService.severities.associateWith { level -> findings.count { it.path("severity").asText() == level } }
            } else emptyMap()
            val status = if (!validPayloads && execution.status == RunStatus.SUCCESS) RunStatus.PARTIAL else execution.status
            record.copy(status = status, finishedAt = Instant.now(), nodeRuns = nodeRuns, error = reason,
                report = report, coverageStatus = coverage, counts = counts, commitsVerified = verified,
                delivery = executor.delivery(workflow, nodeRuns),
                rulesVersions = scans.map { it.rulesVersion.orEmpty() }.toSet())
        } catch (_: TimeoutCancellationException) {
            val stuck = workflow.nodes.filter { observed[it.id]?.status == NodeStatus.RUNNING }.map { it.id }
            val interrupted = onInterrupted(
                if (stuck.isEmpty()) "Превышено время выполнения проверки."
                else "Превышено время выполнения: этап ${stuck.joinToString(", ")}")
            // Отчёт анализаторов сохраняется, даже если время вышло на AI или доставке.
            val scans = reports.scans(workflow, interrupted.nodeRuns)
            val coverage = executor.coverageStatus(workflow, interrupted.nodeRuns)
            if (scans.isNotEmpty() && coverage != "FAILED" && scans.all { it.status != NodeStatus.FAILED }) {
                val report = runCatching { reports.make(record, workflow, interrupted.nodeRuns, coverage, null, null) }.getOrNull()
                val findings = report?.let(::findingsOf).orEmpty()
                val counts = ReportService.severities.associateWith { level ->
                    findings.count { it.path("severity").asText() == level }
                }
                interrupted.copy(status = RunStatus.PARTIAL, coverageStatus = coverage, report = report,
                    counts = if (coverage == "COMPLETE" || findings.isNotEmpty()) counts else emptyMap(),
                    error = "Истекло время выполнения: отчёт анализаторов сохранён, остальные шаги не завершены.")
            } else interrupted
        } catch (_: Throwable) {
            // Любой сбой, включая Error, обязан завершить запуск, а не оставить его в RUNNING.
            onInterrupted("Не удалось завершить запуск.")
        } finally {
            withContext(NonCancellable + Dispatchers.IO) {
                workDirectory?.let { directory -> runCatching { deleteTree(directory) } }
            }
        }
        withContext(NonCancellable + Dispatchers.IO) {
            try {
                decisions.finish(final)
            } catch (_: Throwable) {
                // Итоговое событие run.status должно дойти до интерфейса в любом случае.
                history.finish(final)
            }
        }
        return final
    }

    /** Корень проверенного проекта в рабочей папке запуска: папка единственной ноды-источника плюс `subdir`. */
    private fun snapshotProject(workflow: Workflow, runs: List<NodeRun>, directory: Path): Path? {
        val source = workflow.nodes.filter { it.type in setOf("source.repo", "source.archive") }.singleOrNull() ?: return null
        val receipt = runs.firstOrNull { it.nodeId == source.id }?.output?.get("revision")
        val subdir = when (receipt) {
            is Map<*, *> -> receipt["subdir"] as? String
            is JsonNode -> receipt.path("subdir").textValue()
            else -> null
        }.orEmpty()
        val base = directory.resolve(source.id).toAbsolutePath().normalize()
        val project = if (subdir.isEmpty()) base else base.resolve(subdir).normalize()
        return project.takeIf { it.startsWith(base) && Files.isDirectory(it) }
    }

    private fun sourceRevision(workflow: Workflow, runs: List<NodeRun>, scans: List<NodeRun>): JsonNode? {
        val byId = runs.associateBy { it.nodeId }
        val nodes = workflow.nodes.associateBy { it.id }
        val incoming = workflow.edges.groupBy { it.to.node }
        fun sourcesOf(id: String): Set<String> {
            val seen = mutableSetOf<String>()
            val sources = mutableSetOf<String>()
            val pending = ArrayDeque(listOf(id))
            while (pending.isNotEmpty()) {
                val node = pending.removeFirst()
                if (!seen.add(node)) continue
                if (nodes[node]?.type in setOf("source.repo", "source.archive")) {
                    sources.add(node)
                    continue
                }
                for (edge in incoming[node].orEmpty()) {
                    if (byId[edge.from.node]?.output?.containsKey(edge.from.port) == true) pending.add(edge.from.node)
                }
            }
            return sources
        }
        val revisions = mutableSetOf<JsonNode>()
        for (scan in scans) {
            val sources = sourcesOf(scan.nodeId)
            if (sources.isEmpty()) return null
            for (source in sources) {
                val receipt = byId[source]?.output?.get("revision") as? JsonNode ?: return null
                revisions.add(receipt)
            }
        }
        return revisions.singleOrNull()
    }

    companion object {
        const val AI_RUN_SECONDS = 240L
        const val BASE_RUN_SECONDS = 120L

        /** Бюджет времени запуска: базовые 120 с, при ai.explain в графе - RUN_TIMEOUT_SECONDS (240 с), плюс ожидание решений. */
        fun runBudgetMillis(hasAi: Boolean, aiSeconds: Long, reviewSeconds: Long): Long =
            ((if (hasAi) maxOf(aiSeconds, BASE_RUN_SECONDS) else BASE_RUN_SECONDS) + reviewSeconds) * 1000

        private val uuid = Regex("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    }
}

data class RunTicket(val id: String, val completion: Deferred<RunRecord>)
