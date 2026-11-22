package workflow.app

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MaxUploadSizeExceededException
import workflow.engine.*
import workflow.nodes.InputRejected

@RestController
@RequestMapping("/api")
class WorkflowController(
    private val workflows: WorkflowStore,
    private val registry: NodeRegistry,
    private val validator: GraphValidator,
    private val repositories: RepositorySettingsStore,
) {
    @GetMapping("/nodes")
    fun catalog() = registry.nodes.map { node ->
        mapOf("type" to node.type, "title" to node.title, "category" to node.category,
            "description" to node.description,
            "inputs" to node.inputs, "outputs" to node.outputs, "paramsSchema" to node.paramsSchema,
            "secretParams" to node.secretParams.sorted())
    }

    @GetMapping("/workflows") fun list() = workflows.list()
    @GetMapping("/workflows/{id}") fun get(@PathVariable id: String) = workflows.get(id)

    @PostMapping("/workflows")
    @ResponseStatus(HttpStatus.CREATED)
    fun create(@RequestBody workflow: Workflow): Workflow {
        repositories.approveGraph(workflow)
        return workflows.create(workflow)
    }

    @PutMapping("/workflows/{id}")
    fun update(@PathVariable id: String, @RequestBody workflow: Workflow): Workflow {
        repositories.approveGraph(workflow)
        return workflows.update(id, workflow)
    }

    @DeleteMapping("/workflows/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun delete(@PathVariable id: String) = workflows.delete(id)

    @PostMapping("/workflows/validate")
    fun validate(@RequestBody workflow: Workflow) = mapOf("errors" to validator.validate(workflow))
}

@RestControllerAdvice
class ApiErrors {
    @ExceptionHandler(ReviewDenied::class)
    fun reviewDenied() = error(401, "UNAUTHORIZED", "Проверьте APP_REVIEW_TOKEN")

    @ExceptionHandler(Unauthorized::class)
    fun unauthorized() = error(401, "UNAUTHORIZED", "Проверьте CI_TOKEN")

    @ExceptionHandler(InvalidGraph::class)
    fun invalidGraph(error: InvalidGraph) = ResponseEntity.status(422).body(
        mapOf("code" to "INVALID_GRAPH", "message" to error.message, "details" to mapOf("errors" to error.errors),
            "errors" to error.errors),
    )

    @ExceptionHandler(RateLimited::class)
    fun rateLimited(cause: RateLimited) = error(429, "RATE_LIMITED", cause.message ?: "Слишком много запросов")

    @ExceptionHandler(MissingResource::class)
    fun missing() = error(404, "NOT_FOUND", "Запись не найдена")

    @ExceptionHandler(NoAutofix::class)
    fun noAutofix(cause: NoAutofix) = error(404, "NOT_FOUND", cause.message ?: "Автоисправление не поддерживается")

    @ExceptionHandler(Gone::class)
    fun gone(cause: Gone) = error(410, "GONE", cause.message ?: "Ресурс больше недоступен")

    @ExceptionHandler(Conflict::class)
    fun conflict(cause: Conflict) = error(409, "CONFLICT", cause.message ?: "Конфликт")

    @ExceptionHandler(IntegrationUnavailable::class)
    fun unavailable(cause: IntegrationUnavailable) = error(503, "INTEGRATION_UNAVAILABLE", cause.message ?: "Интеграция недоступна")

    @ExceptionHandler(InvalidLlmWorkflow::class)
    fun invalidLlmWorkflow(cause: InvalidLlmWorkflow) =
        error(502, "INVALID_LLM_WORKFLOW", requireNotNull(cause.message))

    @ExceptionHandler(InputRejected::class)
    fun badInput(cause: InputRejected) = error(422, "INVALID_INPUT", cause.message ?: "Некорректные данные")

    @ExceptionHandler(MaxUploadSizeExceededException::class)
    fun archiveLimit() = error(413, "UPLOAD_LIMIT", "Архив превышает 25 МБ")

    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException::class)
    fun badJson() = error(400, "INVALID_JSON", "Проверьте формат JSON")
}

internal fun error(status: Int, code: String, message: String): ResponseEntity<Map<String, String>> =
    ResponseEntity.status(status).body(mapOf("code" to code, "message" to message))
