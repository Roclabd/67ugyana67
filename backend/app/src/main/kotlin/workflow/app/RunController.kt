package workflow.app

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonUnwrapped
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.annotation.PreDestroy
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ContentDisposition
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter
import workflow.engine.NodeRun
import workflow.engine.Delivery
import workflow.engine.RunStatus
import workflow.nodes.InputRejected
import workflow.nodes.validRepositoryUrl
import workflow.nodes.SafeArchives
import workflow.nodes.deleteTree
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore

data class RunRequest(val source: JsonNode? = null)

data class RunSummary(
    val runId: String,
    val workflowId: String,
    val workflowName: String?,
    val status: RunStatus,
    @get:JsonInclude(JsonInclude.Include.ALWAYS) val coverageStatus: String?,
    val counts: Map<String, Int>,
    val trigger: String?,
    val repoUrl: String?,
    /** Загруженный архив, с которого запущена проверка (ZIP-проекты: повторный запуск без новой загрузки). */
    val uploadId: String?,
    val error: String?,
    val delivery: Delivery?,
    val startedAt: Instant,
    @get:JsonInclude(JsonInclude.Include.ALWAYS) val finishedAt: Instant?,
)

data class RunDetails(
    @get:JsonUnwrapped val summary: RunSummary,
    val workflowVersion: Long,
    val nodeRuns: List<NodeRun>,
    @get:JsonInclude(JsonInclude.Include.ALWAYS) val report: JsonNode?,
) {
    val id: String get() = summary.runId
}

@RestController
@RequestMapping("/api")
class RunController(
    private val history: RunStore,
    private val service: RunService,
    private val reports: ReportService,
    private val json: ObjectMapper,
    private val repositories: RepositorySettingsStore,
    private val demo: DemoMode,
    @Value("\${workflow.data-dir:data}") private val data: String,
) {
    private val sseThreads = Executors.newVirtualThreadPerTaskExecutor()
    private val sseSlots = Semaphore(32)

    @PreDestroy fun close() { sseThreads.shutdownNow() }

    @PostMapping("/workflows/{id}/run")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun start(
        @PathVariable id: String,
        @RequestBody(required = false) request: RunRequest?,
        http: jakarta.servlet.http.HttpServletRequest,
    ): Map<String, String> {
        val trigger = json.createObjectNode().put("kind", "manual")
        request?.source?.let { trigger.set<JsonNode>("source", it) }
        // Ссылка, введённая пользователем при запуске, сама является разрешением на этот репозиторий.
        request?.source?.takeIf { it.path("kind").asText() == "repo" }?.path("url")?.asText("")?.let(repositories::approve)
        val release = demo.claimRun(http)
        try {
            val ticket = service.start(id, trigger)
            ticket.completion.invokeOnCompletion { release() }
            return mapOf("runId" to ticket.id)
        } catch (error: Throwable) {
            release()
            throw error
        }
    }

    @GetMapping("/runs")
    fun list(@RequestParam(required = false) workflowId: String?) = history.list(workflowId).map(RunRecord::summary)

    @GetMapping("/runs/{id}")
    fun get(@PathVariable id: String): RunDetails {
        val run = history.get(id)
        return RunDetails(run.summary(), run.workflowVersion, run.nodeRuns, run.report)
    }

    @GetMapping("/runs/{id}/report.json", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun organizer(@PathVariable id: String) = reports.organizer(report(id))

    @GetMapping("/runs/{id}/report.md", produces = ["text/markdown;charset=UTF-8"])
    fun markdown(@PathVariable id: String) = reports.markdown(report(id))

    @GetMapping("/runs/{id}/report.sarif", produces = ["application/sarif+json"])
    fun sarif(@PathVariable id: String): ResponseEntity<JsonNode> = ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename("report.sarif").build().toString())
        .body(reports.sarif(report(id)))

    @GetMapping("/runs/{id}/report.pdf", produces = ["application/pdf"])
    fun pdf(@PathVariable id: String): ResponseEntity<ByteArray> {
        val run = history.get(id)
        val report = run.report ?: throw MissingResource()
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_PDF)
            .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename("report-${id.take(8)}.pdf").build().toString())
            .body(reports.pdf(report, run.pdfMeta()))
    }

    private fun report(id: String): JsonNode = history.get(id).report ?: throw MissingResource()

    @GetMapping("/runs/{id}/events", produces = [MediaType.TEXT_EVENT_STREAM_VALUE])
    fun events(@PathVariable id: String, @RequestHeader("Last-Event-ID", required = false) lastId: String?): SseEmitter {
        history.get(id)
        if (!sseSlots.tryAcquire()) throw Conflict("Достигнут лимит подписок на запуски")
        val emitter = SseEmitter(180_000L)
        val task = sseThreads.submit {
            try {
                var cursor = lastId?.toLongOrNull()?.coerceAtLeast(0) ?: 0
                var idle = 0
                while (!Thread.currentThread().isInterrupted) {
                    val finished = history.get(id).status != RunStatus.RUNNING
                    val batch = history.events(id, cursor)
                    for (event in batch) {
                        emitter.send(SseEmitter.event().id(event.id.toString()).name(event.name).data(event.data))
                        cursor = event.id
                    }
                    if (batch.size == 100) continue
                    if (finished) break
                    if (++idle % 30 == 0) emitter.send(SseEmitter.event().comment("heartbeat"))
                    Thread.sleep(300)
                }
                emitter.complete()
            } catch (_: InterruptedException) {
                emitter.complete()
            } catch (_: IOException) {
                emitter.complete()
            } catch (error: Exception) {
                emitter.completeWithError(error)
            } finally {
                sseSlots.release()
            }
        }
        emitter.onCompletion { task.cancel(true) }
        emitter.onTimeout { task.cancel(true) }
        return emitter
    }

    @PostMapping("/uploads", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    @ResponseStatus(HttpStatus.CREATED)
    fun upload(@RequestPart("file") file: MultipartFile, http: jakarta.servlet.http.HttpServletRequest): Map<String, String> {
        demo.claimUpload(http)
        if (file.size !in 1..SafeArchives.MAX_COMPRESSED) throw InputRejected("Нужен ZIP-архив до 25 МБ")
        val root = Files.createDirectories(Path.of(data).toAbsolutePath().resolve("uploads"))
        val temporary = Files.createTempDirectory(root, "check-")
        val archive = temporary.resolve("upload.zip")
        try {
            file.transferTo(archive)
            try {
                SafeArchives.extract(archive, temporary.resolve("content"))
            } catch (_: Exception) {
                throw InputRejected("Некорректный ZIP-архив или превышен лимит распаковки")
            }
            val id = UUID.randomUUID().toString()
            Files.move(archive, root.resolve("$id.zip"))
            return mapOf("uploadId" to id)
        } finally {
            deleteTree(temporary)
        }
    }
}

private val displaySeverities = ReportService.severities.filterNot { it == "INFO" }

private fun RunRecord.summary() = RunSummary(
    runId = id,
    workflowId = workflowId,
    workflowName = workflowName,
    status = status,
    coverageStatus = coverageStatus.takeUnless { status == RunStatus.RUNNING },
    counts = displaySeverities.associateWith { counts[it] ?: 0 },
    trigger = trigger.path("kind").textValue(),
    repoUrl = repositoryUrl(),
    uploadId = trigger.path("source").takeIf { it.path("kind").asText() == "upload" }?.path("uploadId")?.textValue(),
    error = error,
    delivery = delivery,
    startedAt = startedAt,
    finishedAt = finishedAt,
)


/** Поля запуска для титульного блока PDF: то, чего нет в самом отчёте. */
private fun RunRecord.pdfMeta(): JsonNode {
    val factory = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
    val node = factory.objectNode()
    workflowName?.let { node.put("workflowName", it) }
    finishedAt?.let { node.put("finishedAt", it.toString()) }
    val revisions = nodeRuns.mapNotNull { run ->
        when (val revision = run.output["revision"]) {
            is JsonNode -> revision.takeIf(JsonNode::isObject)
            is Map<*, *> -> factory.objectNode().also { o ->
                revision.forEach { (k, v) -> if (k is String && v is String) o.put(k, v) }
            }
            else -> null
        }
    }
    val source = repositoryUrl() ?: revisions.firstOrNull()?.let { "ZIP-архив (загруженный проект)" }
    source?.let { node.put("source", it) }
    revisions.firstNotNullOfOrNull { it.path("commitSha").textValue()?.takeIf(String::isNotBlank) }
        ?.let { node.put("commit", it) }
    return node
}

private fun RunRecord.repositoryUrl(): String? {
    val resolved = nodeRuns.mapNotNull {
        val url = when (val revision = it.output["revision"]) {
            is Map<*, *> -> revision["repoUrl"] as? String
            is JsonNode -> revision.path("repoUrl").textValue()
            else -> null
        }
        url?.takeIf(::validRepositoryUrl)
    }.distinct()
    if (resolved.isNotEmpty()) return resolved.singleOrNull()
    val requested = trigger.path("source")
    return requested.path("url").textValue()?.takeIf {
        requested.path("kind").asText() == "repo" && validRepositoryUrl(it)
    }
}
