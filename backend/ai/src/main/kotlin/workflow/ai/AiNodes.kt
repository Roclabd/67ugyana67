package workflow.ai

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import codeguard.analyzers.model.ProjectModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import org.apache.commons.logging.LogFactory
import org.springframework.beans.factory.config.ConfigurableBeanFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import org.springframework.core.env.Environment
import ru.codeguard.ai.AiExplainer
import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.llm.AiLog
import ru.codeguard.ai.llm.ChatMessage
import ru.codeguard.ai.llm.LlmReply
import ru.codeguard.ai.llm.LlmUnavailableException
import ru.codeguard.ai.llm.FileResponseCache
import ru.codeguard.ai.llm.LlmClient
import ru.codeguard.ai.llm.LlmConfig
import ru.codeguard.ai.llm.OpenAiCompatibleClient
import ru.codeguard.ai.llm.ResponseCache
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.ai.model.AiLocation
import ru.codeguard.ai.model.AiReportStatus
import ru.codeguard.ai.model.AiResult
import ru.codeguard.ai.model.ReportAi
import ru.codeguard.ai.model.UsefulnessSummary
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import workflow.engine.ValidatedExplanation
import workflow.engine.WorkflowGenerator
import java.nio.file.Files
import java.nio.file.Paths

/**
 * Подключение AI-слоя к платформе. Провайдер — переменные LLM_BASE_URL, LLM_MODEL, LLM_API_KEY
 * (окружение или .env через spring.config.import): внешний API ↔ Ollama/vLLM меняются настройками, без кода.
 * Без настроек нода работает и честно помечает «объяснения не получены», генератор сценариев не регистрируется.
 */
@Configuration(proxyBeanMethods = false)
class AiConfiguration(environment: Environment) {
    private val settings = SETTINGS.mapNotNull { key -> environment.getProperty(key)?.let { key to it } }.toMap()
    private val runtime = LlmRuntime(LlmConfig.fromEnv(settings))
    private val budget = settings["LLM_NODE_BUDGET_SECONDS"]?.toLongOrNull()?.coerceIn(10, 100) ?: DEFAULT_BUDGET_SECONDS
    private val cache = FileResponseCache(Paths.get(settings["LLM_CACHE_DIR"] ?: "data/llm-cache"))
    private val log = springLog()

    /** Текущий провайдер: из .env при старте, дальше — экран «Настройки LLM» (до перезапуска). */
    @Bean
    fun llmRuntime(): LlmRuntime = runtime

    @Bean
    fun aiExplainNode(): NodeDefinition = AiExplainNode(runtime::client, loadAdvisories(), cache, log, budget)

    /**
     * null — LLM не настроена при старте: сервер отвечает «генерация недоступна», а не падает.
     * Иначе генератор берёт провайдера, выбранного в настройках на момент запроса.
     * prototype: контроллер берёт генератор через ObjectProvider на каждый запрос — LLM, настроенная на экране
     * настроек после старта без .env, сразу включает генерацию без перезапуска.
     */
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    fun workflowGenerator(): WorkflowGenerator? = runtime.client()?.let { LlmWorkflowGenerator(runtime.switchable(), cache, log) }

    companion object {
        private val SETTINGS = listOf("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "LLM_TIMEOUT_SECONDS", "LLM_MAX_ATTEMPTS", "LLM_JSON_MODE", "LLM_CACHE_DIR", "LLM_NODE_BUDGET_SECONDS", "APP_OUTBOUND_PROXY")

        /** Справочник SCA: ресурс модуля C (/sca/vulnerabilities.json), иначе копия учебного набора. Нет — пустой: CVE из текста вырезаются. */
        fun loadAdvisories(): Advisories =
            AiConfiguration::class.java.getResourceAsStream("/sca/vulnerabilities.json")?.use { Advisories.load(it) }
                ?: Advisories.load(Paths.get("fixtures/training/vulnerability-database/vulnerabilities.json"))

        /** Журнал обращений к модели — одна JSON-строка на событие, без кода, промптов и секретов. */
        private fun springLog(): AiLog {
            val logger = LogFactory.getLog("workflow.ai.llm")
            val json = jacksonObjectMapper()
            return AiLog { name, fields -> logger.info(json.writeValueAsString(mapOf("event" to name) + fields)) }
        }
    }
}

/**
 * Нода «LLM: объяснить находки». Вход — находки (и, по желанию, модель проекта для коротких фрагментов кода).
 * Выход — те же находки с полем `ai` (только прошедшее валидатор) и проверенное объяснение для отчёта и уведомлений.
 *
 * Инварианты 5.8: набор находок на выходе равен входу; модель недоступна или ответ не прошёл проверку —
 * статус PARTIAL и явное «объяснения не получены», находки уходят дальше в любом случае.
 */
class AiExplainNode(
    /** Текущий клиент на момент запуска ноды: провайдера можно переключить в настройках (LlmSettingsController). */
    private val client: () -> LlmClient?,
    private val advisories: Advisories,
    private val cache: ResponseCache?,
    private val log: AiLog = AiLog.NONE,
    /**
     * Сколько нода ждёт модель в сумме. Весь запуск ограничен 120 с: медленная LLM не должна сжечь запуск
     * вместе с отчётом. Не успели — оставшиеся находки уходят с «объяснение не получено».
     */
    private val budgetSeconds: Long = DEFAULT_BUDGET_SECONDS,
) : NodeDefinition {
    constructor(client: LlmClient?, advisories: Advisories, cache: ResponseCache?, log: AiLog = AiLog.NONE, budgetSeconds: Long = DEFAULT_BUDGET_SECONDS) :
        this({ client }, advisories, cache, log, budgetSeconds)

    override val type = "ai.explain"
    override val title = "LLM: объяснить находки"
    override val description = "Объясняет риски простым языком, предлагает исправления и группирует связанные находки. Находки не добавляет и не снимает."
    override val category = NodeCategory.AI
    override val inputs = listOf(PortSpec("findings", PortType.FINDINGS), PortSpec("model", PortType.PROJECT_MODEL, required = false))
    override val outputs = listOf(PortSpec("findings", PortType.FINDINGS), PortSpec("explanation", PortType.ANY))
    override val paramsSchema: JsonNode = JsonNodeFactory.instance.objectNode().put("type", "object").put("additionalProperties", false)

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
        val original = FindingsJson.list(input.ports["findings"])
        val model = input.ports["model"] as? ProjectModel
        val texts = model?.files?.associate { it.path to it.text }.orEmpty()
        val findings = FindingsJson.toAi(original, advisories)
        if (model == null) ctx.log("Модель проекта не подключена: объяснения без фрагментов кода")

        val source = { path: String -> texts[path] }
        val current = client()
        val deadline = System.nanoTime() + budgetSeconds * 1_000_000_000
        val timeoutText = "LLM не ответила за $budgetSeconds с"
        // Новые запросы после срока не начинаются (уже полученные объяснения сохраняются);
        // зависший запрос обрывает внешний таймаут, тогда все объяснения — «не получены».
        val result = withTimeoutOrNull((budgetSeconds + 5) * 1000) {
            runInterruptible(Dispatchers.IO) {
                AiExplainer(current?.let { DeadlineClient(it, deadline, timeoutText) }, source, advisories, cache, log).explain(findings)
            }
        } ?: AiExplainer(current?.let { DeadlineClient(it, Long.MIN_VALUE, timeoutText) }, source, advisories, cache, log).explain(findings)
        val report = result.report
        ctx.log("AI: ${report.status}${report.reason?.let { " — $it" } ?: ""}; ответов ${report.validator.responses}, " +
            "вырезано CVE ${report.validator.rejectedCves}, мест ${report.validator.rejectedLocations}")
        return NodeOutput(
            ports = mapOf(
                "findings" to FindingsJson.withAi(original, findings, result),
                "explanation" to AiExplanation(ctx.redact(ExplanationText.render(findings, result)), report, result.usefulness),
            ),
            status = if (report.status == AiReportStatus.OK) NodeStatus.SUCCESS else NodeStatus.PARTIAL,
        )
    }
}

/** Клиент со сроком: после него запросы к модели не отправляются, это обычная «модель недоступна». */
private class DeadlineClient(private val delegate: LlmClient, private val deadline: Long, private val reason: String) : LlmClient {
    override val config get() = delegate.config
    override fun chat(messages: List<ChatMessage>): LlmReply {
        if (deadline == Long.MIN_VALUE || System.nanoTime() - deadline >= 0) throw LlmUnavailableException(reason)
        return delegate.chat(messages)
    }
}

/**
 * Проверенное объяснение — значение порта `explanation`. Уведомления и отчёт берут только [text];
 * [ai] (раздел `ai` отчёта: статус, модель, счётчики валидатора) и [usefulness] видны в данных ноды.
 */
data class AiExplanation(override val text: String, val ai: ReportAi, val usefulness: UsefulnessSummary) : ValidatedExplanation

/** Находки в форме contracts/finding.schema.json ↔ вход AI-слоя. */
object FindingsJson {
    private val json: ObjectMapper = jacksonObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)

    /** Порт FINDINGS: массив находок (анализатор), список JsonNode (logic.merge) или объект с полем findings (отчёт). */
    fun list(value: Any?): List<ObjectNode> {
        if (value == null) return emptyList()
        val tree: JsonNode = value as? JsonNode ?: json.valueToTree(value)
        val array = if (tree.isArray) tree else tree.path("findings")
        return array.filterIsInstance<ObjectNode>()
    }

    /**
     * Внутренние id для AI-слоя уникальны по построению: id находки, при повторе — с суффиксом.
     * Наружу уходят исходные объекты находок, id не меняются.
     */
    fun toAi(findings: List<ObjectNode>, advisories: Advisories): List<AiFinding> {
        val seen = hashMapOf<String, Int>()
        return findings.mapIndexed { index, f ->
            val base = f.path("id").asText("").ifEmpty { "f-${index + 1}" }
            val n = seen.merge(base, 1, Int::plus)!!
            val category = f.path("category").asText()
            val advisoryId = f.text("advisoryId")
            AiFinding(
                id = if (n == 1) base else "$base#$n",
                category = category,
                findingClass = f.text("class"),
                severity = f.path("severity").asText("MEDIUM"),
                path = f.path("path").asText(),
                line = f.get("line")?.takeIf { it.isInt }?.asInt(),
                endLine = f.get("endLine")?.takeIf { it.isInt }?.asInt(),
                title = f.text("title"),
                description = f.text("description"),
                remediation = f.text("remediation"),
                evidence = f.path("evidence").map { e ->
                    AiLocation(e.path("path").asText(), e.path("line").asInt(), e.get("endLine")?.asInt(), e.text("note"))
                },
                // Только маска: сырого значения секрета в находке нет, secretHash в модель не передаётся.
                secretMasked = f.text("secretMasked"),
                group = f.text("group"),
                artifact = f.text("artifact"),
                version = f.text("version"),
                advisoryId = advisoryId,
                fixedVersions = f.path("fixedVersions").map { it.asText() }
                    .ifEmpty { if (category == "SCA" && advisoryId != null) advisories.fixedVersionsOf(advisoryId) else emptyList() },
            )
        }
    }

    /** Исходные находки + поле `ai`. Порядок и состав не меняются (это проверяет и AiExplainer). */
    fun withAi(original: List<ObjectNode>, findings: List<AiFinding>, result: AiResult): ArrayNode {
        val out = JsonNodeFactory.instance.arrayNode()
        original.zip(findings).forEach { (node, f) ->
            val copy = node.deepCopy()
            result.findings[f.id]?.let { copy.set<JsonNode>("ai", json.valueToTree(it)) }
            out.add(copy)
        }
        return out
    }

    private fun JsonNode.text(field: String): String? = get(field)?.takeIf { it.isTextual }?.asText()?.takeIf { it.isNotBlank() }
}

/** Текст для уведомлений: только прошедшее валидатор; при отказе модели — явная причина. */
object ExplanationText {
    fun render(findings: List<AiFinding>, result: AiResult): String {
        val r = result.report
        val ok = result.findings.values.count { it.status == ru.codeguard.ai.model.AiFindingStatus.OK }
        val byId = findings.associateBy { it.id }
        fun label(id: String) = byId[id]?.let { f ->
            val what = f.findingClass ?: listOfNotNull(f.artifact, f.version).joinToString(" ").ifEmpty { f.category }
            "$what · ${f.path}${f.line?.let { ":$it" } ?: ""}"
        } ?: id
        return buildString {
            val model = listOfNotNull(r.model, r.provider).joinToString(", ")
            when (r.status) {
                AiReportStatus.NOT_RECEIVED -> {
                    appendLine("AI-анализ: объяснения не получены — ${r.reason ?: "причина не указана"}.")
                    appendLine("Находки определены анализаторами и переданы полностью.")
                    return@buildString
                }
                else -> appendLine("AI-анализ ($model): объяснения получены для $ok из ${findings.size} находок.")
            }
            r.summary?.let { appendLine(it) }
            if (r.priorities.isNotEmpty()) {
                appendLine("Порядок исправления:")
                r.priorities.take(5).forEachIndexed { i, id -> appendLine("${i + 1}. ${label(id)}") }
            }
            if (r.groups.isNotEmpty()) {
                appendLine("Связанные находки:")
                r.groups.take(3).forEach { g -> appendLine("• ${g.title}: ${g.story}") }
            }
            val v = r.validator
            append("Валидатор: вырезано выдуманных CVE ${v.rejectedCves}, мест в коде ${v.rejectedLocations}, ссылок на находки ${v.rejectedFindingRefs}.")
        }.trim()
    }
}

/** Весь запуск — 120 с; источник и анализаторы — секунды, остальное — модели. */
const val DEFAULT_BUDGET_SECONDS = 70L
