package ru.codeguard.ai

import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.context.CodeContext
import ru.codeguard.ai.llm.AiLog
import ru.codeguard.ai.llm.JsonCompletion
import ru.codeguard.ai.llm.LlmClient
import ru.codeguard.ai.llm.ResponseCache
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.ai.model.AiFindingStatus
import ru.codeguard.ai.model.AiReportStatus
import ru.codeguard.ai.model.AiResult
import ru.codeguard.ai.model.FindingAi
import ru.codeguard.ai.model.ReportAi
import ru.codeguard.ai.model.UsefulnessSummary
import ru.codeguard.ai.model.ValidatorStats
import ru.codeguard.ai.prompt.Prompts
import ru.codeguard.ai.usefulness.Usefulness
import ru.codeguard.ai.validate.ParsedBatch
import ru.codeguard.ai.validate.ParsedSummary
import ru.codeguard.ai.validate.RawExplanation
import ru.codeguard.ai.validate.ResponseValidator

/**
 * AI-слой: объясняет и группирует находки анализаторов.
 *
 * Инварианты (закреплены тестами):
 *  - LLM не меняет набор находок: на выходе — ровно те же id, что на входе, у каждой ровно одно поле ai;
 *  - в отчёт и уведомление попадают только объяснения, прошедшие валидатор; остальные — «не получено»/«отклонено» с причиной;
 *  - недоступная модель — явный статус NOT_RECEIVED, а не пустое поле и не исключение;
 *  - сырые значения секретов в промпт не попадают и на выходе маскируются повторно;
 *  - версия обновления SCA выбирается детерминированно из справочника, модель её только объясняет.
 *
 * @param client null — LLM не настроена: объяснений нет, отчёт уходит с явной пометкой.
 * @param source текст файла проекта по относительному пути — для коротких фрагментов кода.
 */
class AiExplainer(
    private val client: LlmClient?,
    private val source: (String) -> String?,
    private val advisories: Advisories = Advisories.EMPTY,
    private val cache: ResponseCache? = null,
    private val log: AiLog = AiLog.NONE,
    private val batchSize: Int = 6,
) {
    fun explain(findings: List<AiFinding>): AiResult {
        val stats = ValidatorStats()
        val validator = ResponseValidator(findings, advisories)
        val usefulness = Usefulness(advisories, source)
        val context = CodeContext(source).apply { registerSecrets(findings) }
        val out = linkedMapOf<String, FindingAi>()
        val recommended: Map<String, String?> = findings.filter { it.category == "SCA" }
            .associate { it.id to advisories.recommend(it.group, it.artifact, it.version, it.fixedVersions) }

        if (client == null) {
            findings.forEach { out[it.id] = notReceived(it, recommended, "LLM не настроена (LLM_BASE_URL / LLM_MODEL не заданы)") }
            return result(findings, out, recommended, ReportAi(AiReportStatus.NOT_RECEIVED, null, null, null, emptyList(), emptyList(), stats, "LLM не настроена"))
        }

        val completion = JsonCompletion(client, cache, log)
        var unavailable: String? = null

        /** Один запрос объяснений для пакета; возвращает разобранный ответ или null с записью причины. */
        fun request(batch: List<AiFinding>): Pair<ParsedBatch?, String?> {
            val ids = batch.map { it.id }.toSet()
            val outcome = completion.complete("explain", Prompts.PROMPT_VERSION, Prompts.explainMessages(batch, context, recommended)) { node -> validator.checkExplain(node, ids) }
            stats.schemaFailures += outcome.schemaFailures
            stats.retries += (outcome.attempts - 1).coerceAtLeast(0)
            if (outcome.fromCache) stats.cacheHits++
            if (outcome.value == null) {
                if (outcome.unavailable) unavailable = outcome.error
                return null to (outcome.error ?: "Объяснение не получено")
            }
            stats.responses++
            stats.rejectedFindingRefs += outcome.value.unknownIds.size
            stats.rejectedDisputes += outcome.value.disputedIds.size
            stats.injectionSuspected += outcome.value.disputedIds.size
            return outcome.value to null
        }

        for (batch in findings.chunked(batchSize)) {
            if (unavailable != null) {
                batch.forEach { out[it.id] = notReceived(it, recommended, unavailable!!) }
                continue
            }
            val (parsed, error) = request(batch)
            if (parsed == null) {
                batch.forEach { out[it.id] = notReceived(it, recommended, error!!) }
                continue
            }
            val raws = parsed.items.associateBy { it.id }.toMutableMap()
            val rejected = mutableMapOf<String, String>()
            parsed.disputedIds.forEach { rejected[it] = "Модель пыталась оспорить находку — это решают анализаторы, объяснение отклонено" }
            parsed.malformedIds.forEach { rejected[it] = "Ответ модели для этой находки не прошёл проверку схемы" }
            // Пропущенные находки — один дозапрос только по ним.
            val missing = batch.filter { it.id !in raws && it.id !in rejected }
            if (missing.isNotEmpty() && unavailable == null) {
                val (retry, _) = request(missing)
                retry?.items?.forEach { raws[it.id] = it }
                retry?.disputedIds?.forEach { rejected.putIfAbsent(it, "Модель пыталась оспорить находку — это решают анализаторы, объяснение отклонено") }
            }
            for (f in batch) {
                val raw = raws[f.id]
                out[f.id] = when {
                    raw != null -> accept(f, raw, recommended[f.id], validator, usefulness, stats)
                    f.id in rejected -> FindingAi(AiFindingStatus.REJECTED_BY_VALIDATOR, fixSteps = scaSteps(f, recommended[f.id]), recommendedVersion = recommended[f.id], reason = rejected[f.id])
                    else -> notReceived(f, recommended, unavailable ?: "Модель не дала объяснения для этой находки")
                }
            }
        }

        val okCount = out.values.count { it.status == AiFindingStatus.OK }
        var summary: ParsedSummary? = null
        var summaryError: String? = null
        if (okCount > 0 && unavailable == null) {
            val s = completion.complete("summary", Prompts.PROMPT_VERSION, Prompts.summaryMessages(findings)) { node -> validator.checkSummary(node) }
            stats.schemaFailures += s.schemaFailures
            if (s.fromCache) stats.cacheHits++
            if (s.value != null) {
                stats.responses++
                stats.rejectedFindingRefs += s.value.unknownIds
                summary = s.value.copy(
                    summary = validator.sanitize(s.value.summary, validator.summaryScope, stats) ?: s.value.summary,
                    priorities = completePriorities(s.value.priorities, findings),
                    groups = s.value.groups.map { g ->
                        val scope = validator.scopeOfGroup(g.findingIds)
                        g.copy(title = validator.sanitize(g.title, scope, stats) ?: g.title, story = validator.sanitize(g.story, scope, stats) ?: g.story)
                    },
                )
            } else summaryError = s.error
        }
        val status = when {
            okCount == 0 -> AiReportStatus.NOT_RECEIVED
            okCount == findings.size && summary != null -> AiReportStatus.OK
            else -> AiReportStatus.PARTIAL
        }
        val reason = when {
            status == AiReportStatus.NOT_RECEIVED -> unavailable ?: "Ни один ответ модели не прошёл проверку"
            okCount < findings.size -> "Объяснения получены не для всех находок: ${findings.size - okCount} из ${findings.size} без объяснения"
            summary == null -> "Объяснения получены, но резюме и группировка — нет${summaryError?.let { ": $it" } ?: ""}"
            else -> null
        }
        return result(findings, out, recommended, ReportAi(status, client.config.provider, client.config.model, summary?.summary, summary?.priorities.orEmpty(), summary?.groups.orEmpty(), stats, reason))
    }

    /** Принятие объяснения: очистка всех полей; если после очистки по существу ничего не осталось — отклонить. */
    private fun accept(f: AiFinding, raw: RawExplanation, rec: String?, v: ResponseValidator, usefulness: Usefulness, stats: ValidatorStats): FindingAi {
        val scope = v.scopeOf(f)
        fun text(s: String?) = v.sanitizeVersions(v.sanitize(s, scope, stats), f, rec, stats)
        val explanation = text(raw.explanation)
        if (explanation == null || meaningful(explanation) < 10) {
            return FindingAi(AiFindingStatus.REJECTED_BY_VALIDATOR, fixSteps = scaSteps(f, rec), recommendedVersion = rec, reason = "После проверки в объяснении не осталось содержания")
        }
        val fixExample = v.scaFixExample(v.sanitizeCode(raw.fixExample, f, stats), f, rec, stats)
        return FindingAi(
            status = AiFindingStatus.OK,
            explanation = explanation,
            impact = text(raw.impact),
            fixSteps = scaSteps(f, rec) + v.filterScaSteps(raw.fixSteps, f, rec, stats).mapNotNull { v.sanitize(it, scope, stats) },
            fixExample = fixExample,
            recommendedVersion = rec,
            usefulnessChecks = usefulness.checks(f, fixExample, rec),
        )
    }

    private fun meaningful(text: String) = text.replace(Regex("""\[[^\]]*валидатором]"""), "").replace(CodeContext.MASK, "").count { it.isLetterOrDigit() }

    /** Порядок исправления: сначала указанный моделью, затем остальные — по критичности (сервер гарантирует полноту). */
    private fun completePriorities(model: List<String>, findings: List<AiFinding>): List<String> {
        val rank = mapOf("CRITICAL" to 0, "HIGH" to 1, "MEDIUM" to 2, "LOW" to 3)
        return (model + findings.sortedBy { rank[it.severity] ?: 4 }.map { it.id }).distinct()
    }

    /** SCA: первый шаг исправления — детерминированный, из справочника. */
    private fun scaSteps(f: AiFinding, rec: String?): List<String> =
        if (f.category == "SCA" && rec != null) listOf("Обновить ${f.group}:${f.artifact} с ${f.version} до $rec (первая исправленная версия по справочнику).") else emptyList()

    private fun notReceived(f: AiFinding, recommended: Map<String, String?>, reason: String) =
        FindingAi(AiFindingStatus.NOT_RECEIVED, fixSteps = scaSteps(f, recommended[f.id]), recommendedVersion = recommended[f.id], reason = CodeContext.scrubText(reason))

    private fun result(findings: List<AiFinding>, out: Map<String, FindingAi>, recommended: Map<String, String?>, report: ReportAi): AiResult {
        // Инвариант: ровно те же находки, в том же порядке.
        check(out.keys.toList() == findings.map { it.id }) { "AI-слой изменил набор находок" }
        val ok = out.values.filter { it.status == AiFindingStatus.OK }
        val sca = findings.filter { it.category == "SCA" }
        return AiResult(
            out,
            report.copy(reason = report.reason?.let { CodeContext.scrubText(it) }),
            UsefulnessSummary(
                recommendations = ok.size,
                withFixExample = ok.count { it.usefulnessChecks["hasFixExample"] == true },
                fixParses = ok.count { it.usefulnessChecks["fixParses"] == true },
                fixPatternOk = ok.count { it.usefulnessChecks["fixPattern"] == true },
                rerunClean = ok.count { it.usefulnessChecks["rerunClean"] == true },
                // один предикат и для поля находки, и для метрики
                scaTargetSafe = sca.count { advisories.targetSafe(it.group, it.artifact, it.version, recommended[it.id]) },
                scaTotal = sca.size,
            ),
        )
    }
}
