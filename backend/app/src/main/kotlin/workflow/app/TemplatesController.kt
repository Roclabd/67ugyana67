package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.springframework.beans.factory.ObjectProvider
import org.springframework.http.HttpStatus
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.*
import workflow.engine.*
import workflow.nodes.InputRejected
import workflow.nodes.normalizeRepositoryInput
import java.util.UUID

data class TemplateRecord(
    val id: String,
    val name: String,
    val description: String,
    val tags: List<String>,
    val author: String,
    val workflow: Workflow,
) {
    val nodeCount: Int get() = workflow.nodes.size
}
data class PublishTemplate(val workflowId: String, val name: String, val description: String = "")
data class CopyTemplate(val name: String? = null, val repoUrl: String? = null, val recipient: String? = null, val uploadId: String? = null,
    val project: ProjectMeta? = null)
data class GenerateRequest(val text: String)
class IntegrationUnavailable(message: String) : RuntimeException(message)
class InvalidLlmWorkflow : RuntimeException("LLM не вернула корректный сценарий")

@Service
class TemplateLibrary(
    private val db: JdbcTemplate,
    private val json: ObjectMapper,
    private val workflows: WorkflowStore,
    private val validator: GraphValidator,
    private val nodes: NodeRegistry,
    private val repositories: RepositorySettingsStore,
    private val demo: DemoMode,
) {
    fun list(): List<TemplateRecord> = builtIns() + db.query("SELECT payload FROM templates ORDER BY id") { row, _ ->
        json.readValue(row.getString(1), TemplateRecord::class.java)
    }

    fun get(id: String): TemplateRecord = builtIns().find { it.id == id }
        ?: db.query("SELECT payload FROM templates WHERE id = ?",
            { row, _ -> json.readValue(row.getString(1), TemplateRecord::class.java) }, id).singleOrNull()
        ?: throw MissingResource()

    fun publish(request: PublishTemplate): TemplateRecord {
        if (request.name.isBlank() || request.name.length > 160 || request.description.length > 1000) {
            throw InputRejected("Укажите название до 160 и описание до 1000 символов")
        }
        val source = workflows.unlocked(request.workflowId)
        validator.requireValid(source)
        val workflow = workflows.withoutSecrets(source).copy(id = null, name = request.name, version = 0)
        validator.requireValid(workflow)
        val template = TemplateRecord(UUID.randomUUID().toString(), request.name, request.description, emptyList(), "Пользователь", workflow)
        db.update("INSERT INTO templates (id, payload) VALUES (?, ?)", template.id, json.writeValueAsString(template))
        return template
    }

    fun copy(id: String, request: CopyTemplate): Workflow {
        val template = get(id)
        if (demo.enabled && request.recipient != null) throw InputRejected(DEMO_BLOCKED_MESSAGE)
        if (demo.enabled && request.project != null) throw InputRejected(DEMO_BLOCKED_MESSAGE)
        request.project?.let(::requireProject)
        val source = demo.stripNotifications(template.workflow)
        val workflow = source.copy(name = request.name ?: template.name, project = request.project, nodes = source.nodes.map { node ->
            val params = node.params.deepCopy<ObjectNode>()
            if (node.type == "source.repo") request.repoUrl?.let { raw ->
                val input = normalizeRepositoryInput(raw)
                val url = input?.url ?: raw
                if (params.path("url").asText() != url) params.remove(listOf("subdir", "branch", "commitSha"))
                params.put("url", url)
                input?.branch?.let { params.put("branch", it) }
                input?.subdir?.let { params.put("subdir", it) }
            }
            if (node.type == "source.archive") request.uploadId?.let { params.put("uploadId", it) }
            if (node.type == "notify.smtp") request.recipient?.let { params.put("to", it) }
            node.copy(params = params)
        })
        repositories.approveGraph(workflow)
        return workflows.create(workflow)
    }

    private fun builtIns(): List<TemplateRecord> = listOfNotNull(
        builtIn("release", "Полная проверка перед релизом", "Проверка секретов, зависимостей и кода перед релизом.",
            "manual", listOf("secret", "sca", "sast"), output = "notify.telegram"),
        builtIn("daily-secrets", "Секреты каждый день в 14:00 на почту", "Ежедневная проверка секретов с отчётом на почту.",
            "cron", listOf("secret"), "0 0 14 * * *", "notify.smtp"),
        builtIn("ci-gate", "Проверка в CI с блокировкой", "Проверка по SHA коммита из пайплайна.",
            "webhook", listOf("secret", "sca", "sast"), output = "output.report"),
        builtIn("weekly-dependencies", "Зависимости раз в неделю", "Проверка зависимостей по понедельникам в 09:00.",
            "cron", listOf("sca"), "0 0 9 * * MON", "notify.telegram"),
        builtIn("zip-scan", "Проверить ZIP-архив", "Загрузите ZIP и выполните полную проверку без Git.",
            "manual", listOf("secret", "sca", "sast"), output = "output.report", archive = true),
        builtIn("zip-ai", "Проверить ZIP + AI-отчёт", "Загрузите ZIP: секреты, зависимости и код, объяснение находок и отчёт. Без уведомлений.",
            "manual", listOf("secret", "sca", "sast"), output = "output.report", archive = true, ai = true),
        builtIn("pr-new-telegram", "Новые находки в Pull Request → Telegram",
            "Запуск от PR по SHA коммита. После настройки базовой линии отправляет только новые находки.",
            "webhook", listOf("secret", "sca", "sast"), output = "notify.telegram", filter = "logic.only-new"),
        builtIn("nightly-routes", "Ночная проверка с картой маршрутов",
            "Полная проверка в 02:00. Карта доступна на экране запуска.",
            "cron", listOf("secret", "sca", "sast"), "0 0 2 * * *", "output.report", routeMap = true),
        builtIn("critical-approval", "Решение по критической находке",
            "Полная проверка и запрос решения по первой критической находке при полном покрытии.",
            "manual", listOf("secret", "sca", "sast"), output = REVIEW_WAIT_NODE, filter = "logic.filter"),
        codeQuality(),
    )

    /** ZIP → «Проверка качества кода». Без анализаторов безопасности: результат попадает в блок `quality` отчёта. */
    private fun codeQuality(): TemplateRecord? {
        val definition = nodes["analyzer.quality"] ?: return null
        val input = definition.inputs.firstOrNull { it.type == PortType.WORKSPACE } ?: return null
        val graph = Workflow(
            name = "Проверка качества кода",
            nodes = listOf(
                WorkflowNode("start", "trigger.manual", json.createObjectNode()),
                WorkflowNode("source", "source.archive", json.createObjectNode(), Position(270.0, 0.0)),
                WorkflowNode("quality", definition.type, json.createObjectNode(), Position(530.0, 0.0)),
            ),
            edges = listOf(edge("start", "trigger", "source", "trigger"), edge("source", "workspace", "quality", input.name)),
        )
        if (validator.validate(graph).isNotEmpty()) return null
        return TemplateRecord("code-quality", graph.name,
            "Загрузите ZIP со смешанным проектом (Kotlin, Python, JavaScript): синтаксис, типы, ссылки, функциональные дефекты. На проверки безопасности и CI не влияет.",
            listOf("manual", "quality"), "Команда", graph)
    }

    private fun builtIn(id: String, name: String, description: String, trigger: String, checks: List<String>,
        cron: String? = null, output: String, archive: Boolean = false, filter: String? = null,
        routeMap: Boolean = false, ai: Boolean = false): TemplateRecord? {
        val sourceType = if (archive) "source.archive" else "source.repo"
        val sourceParams = json.createObjectNode()
        if (!archive) sourceParams.put("url", "https://github.com/example-org/training")
        val graphNodes = mutableListOf(
            WorkflowNode("start", "trigger.$trigger", json.createObjectNode().apply { cron?.let { put("cron", it) } }),
            WorkflowNode("source", sourceType, sourceParams, Position(270.0, 0.0)),
        )
        val edges = mutableListOf(edge("start", "trigger", "source", "trigger"))
        val model = nodes.nodes.firstOrNull { node ->
            node.inputs.any { it.required && it.type == PortType.WORKSPACE } &&
                node.outputs.any { it.type == PortType.PROJECT_MODEL }
        }
        if (model != null) {
            graphNodes.add(WorkflowNode("model", model.type, position = Position(530.0, -160.0)))
            edges.add(edge("source", "workspace", "model", model.inputs.first { it.type == PortType.WORKSPACE }.name))
        }
        if (routeMap) {
            val modelPort = model?.outputs?.firstOrNull { it.type == PortType.PROJECT_MODEL } ?: return null
            graphNodes.add(WorkflowNode("routes", "output.route-map", position = Position(780.0, -200.0)))
            edges.add(edge("model", modelPort.name, "routes", "model"))
        }
        val scanOutputs = mutableListOf<Pair<String, PortSpec>>()
        for ((index, check) in checks.withIndex()) {
            val definition = nodes["analyzer.$check"] ?: return null
            graphNodes.add(WorkflowNode(check, definition.type, position = Position(780.0, index * 180.0)))
            for (port in definition.inputs) {
                when (port.type) {
                    PortType.WORKSPACE -> edges.add(edge("source", "workspace", check, port.name))
                    PortType.PROJECT_MODEL -> {
                        val modelPort = model?.outputs?.firstOrNull { it.type == PortType.PROJECT_MODEL } ?: return null
                        edges.add(edge("model", modelPort.name, check, port.name))
                    }
                    else -> if (port.required) return null
                }
            }
            scanOutputs.add(check to (definition.outputs.firstOrNull { it.type == PortType.FINDINGS }
                ?: definition.outputs.firstOrNull { it.type == PortType.REPORT } ?: return null))
        }
        val explain = (ai || output in setOf("notify.telegram", "notify.smtp")) && filter == null && nodes["ai.explain"] != null &&
            scanOutputs.all { it.second.type == PortType.FINDINGS }
        val findingsTarget = when {
            explain -> "ai"
            filter != null -> "filter"
            else -> "output"
        }
        if (filter != null) {
            val params = json.createObjectNode()
            if (filter == "logic.filter") params.put("severity", "CRITICAL")
            graphNodes.add(WorkflowNode("filter", filter, params, position = Position(1300.0, 0.0)))
            edges.add(edge("filter", "findings", "output", "findings"))
        }
        graphNodes.add(WorkflowNode("output", output, position = Position(when { explain && ai -> 1570.0; explain -> 1840.0; filter != null -> 1570.0; else -> 1300.0 }, 0.0)))
        if (scanOutputs.size == 1) {
            val (scan, port) = scanOutputs.single()
            edges.add(edge(scan, port.name, findingsTarget, if (port.type == PortType.REPORT) "report" else "findings"))
        } else {
            if (scanOutputs.any { it.second.type != PortType.FINDINGS }) return null
            graphNodes.add(WorkflowNode("merge", "logic.merge", position = Position(1050.0, 0.0)))
            scanOutputs.forEachIndexed { i, (scan, port) -> edges.add(edge(scan, port.name, "merge", "findings${i + 1}")) }
            edges.add(edge("merge", "findings", findingsTarget, "findings"))
        }
        if (explain) {
            graphNodes.add(WorkflowNode("ai", "ai.explain", position = Position(1300.0, 0.0), continueOnError = true))
            if (!ai) graphNodes.add(WorkflowNode("report", "output.report", position = Position(1570.0, 0.0)))
            model?.outputs?.firstOrNull { it.type == PortType.PROJECT_MODEL }?.let {
                edges.add(edge("model", it.name, "ai", "model"))
            }
            val sink = if (ai) "output" else "report"
            edges.add(edge("ai", "findings", sink, "findings"))
            edges.add(edge("ai", "explanation", sink, "explanation"))
            if (!ai) edges.add(edge("report", "report", "output", "report"))
        }
        val graph = Workflow(name = name, nodes = graphNodes, edges = edges)
        if (validator.validate(graph).isNotEmpty()) return null
        return TemplateRecord(id, name, description, listOf(trigger) + checks, "Команда", graph)
    }

    private fun edge(from: String, out: String, to: String, input: String) =
        WorkflowEdge("${from}_${out}_${to}_$input", Endpoint(from, out), Endpoint(to, input))
}

@RestController
@RequestMapping("/api")
class TemplatesController(
    private val library: TemplateLibrary,
    private val generator: ObjectProvider<WorkflowGenerator>,
    private val registry: NodeRegistry,
    private val validator: GraphValidator,
    private val workflows: WorkflowStore,
    private val json: ObjectMapper,
) {
    @GetMapping("/templates") fun list() = library.list().map {
        mapOf("id" to it.id, "name" to it.name, "description" to it.description, "tags" to it.tags,
            "nodeCount" to it.nodeCount, "author" to it.author)
    }
    @GetMapping("/templates/{id}") fun get(@PathVariable id: String) = library.get(id)
    @PostMapping("/templates") @ResponseStatus(HttpStatus.CREATED)
    fun publish(@RequestBody request: PublishTemplate) = library.publish(request)
    @PostMapping("/templates/{id}/copy") @ResponseStatus(HttpStatus.CREATED)
    fun copy(@PathVariable id: String, @RequestBody(required = false) request: CopyTemplate?) =
        library.copy(id, request ?: CopyTemplate())

    @PostMapping("/workflows/generate")
    fun generate(@RequestBody request: GenerateRequest): Map<String, Any> {
        if (request.text.isBlank() || request.text.length > 4000) throw InputRejected("Введите описание до 4000 символов")
        val provider = generator.ifAvailable ?: throw IntegrationUnavailable("LLM не настроена")
        val catalog = registry.nodes.map {
            mapOf("type" to it.type, "category" to it.category, "inputs" to it.inputs, "outputs" to it.outputs,
                "paramsSchema" to it.paramsSchema, "secretParams" to it.secretParams)
        }
        val instructions = """
            Собери Workflow в JSON с полями name, nodes, edges. Используй только типы, параметры и порты из каталога.
            У каждой связи есть id, from:{node,port}, to:{node,port}, у ноды id,type,params,position:{x,y}.
            Не выдумывай учётные данные и адреса доставки. Не заполняй secretParams.
            Для 14:00 каждый день используй cron «0 0 14 * * *», по умолчанию Europe/Moscow.
            Каталог: ${json.writeValueAsString(catalog)}
            Запрос: ${json.writeValueAsString(request.text)}
        """.trimIndent()
        var feedback = emptyList<GraphError>()
        repeat(2) {
            val graph = runBlocking {
                withTimeoutOrNull(30_000) {
                    try {
                        provider.generate(instructions + if (feedback.isEmpty()) "" else "\nИсправь ошибки: ${json.writeValueAsString(feedback)}")
                    } catch (failure: RuntimeException) {
                        // The AI adapter is an optional runtime module.
                        if (failure.javaClass.name == "workflow.ai.LlmWorkflowGenerator\$GenerationFailed") {
                            throw InvalidLlmWorkflow()
                        }
                        throw failure
                    }
                }
            } ?: throw IntegrationUnavailable("LLM не ответила вовремя")
            feedback = generatedErrors(graph, validator, registry)
            if (feedback.isEmpty()) {
                val safe = workflows.withoutSecrets(graph).copy(id = null, version = 0)
                return mapOf("workflow" to safe, "errors" to emptyList<GraphError>())
            }
        }
        throw InvalidLlmWorkflow()
    }
}

internal fun generatedErrors(graph: Workflow, validator: GraphValidator, registry: NodeRegistry): List<GraphError> =
    validator.validate(graph) + graph.nodes.mapNotNull { node ->
        if (registry[node.type]?.secretParams.orEmpty().any { node.params.has(it) }) {
            GraphError("GENERATED_SECRET", "LLM не должна задавать секретные параметры", node.id)
        } else null
    }

/** Метаданные проекта: пока поддерживается только ZIP-проект (`archive`); проекты-репозитории выводятся из ссылки. */
fun requireProject(project: ProjectMeta) {
    if (project.kind != "archive" || project.name.isBlank() || project.name.length > 80) {
        throw InputRejected("Проект: тип archive и имя до 80 символов")
    }
}
