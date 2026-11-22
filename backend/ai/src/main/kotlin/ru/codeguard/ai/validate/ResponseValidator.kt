package ru.codeguard.ai.validate

import com.fasterxml.jackson.databind.JsonNode
import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.context.CodeContext
import ru.codeguard.ai.context.PromptGuard
import ru.codeguard.ai.llm.Checked
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.ai.model.AiGroup
import ru.codeguard.ai.model.ValidatorStats
import java.net.URLDecoder
import java.text.Normalizer

/** Объяснение одной находки, как его вернула модель (до очистки). */
data class RawExplanation(val id: String, val explanation: String, val impact: String?, val fixSteps: List<String>, val fixExample: String?)

data class ParsedBatch(
    val items: List<RawExplanation>,
    val unknownIds: List<String>,
    val malformedIds: List<String>,
    /** Объяснения, в которых модель оспаривает находку («ложное срабатывание», «действий не требуется») — отклоняются. */
    val disputedIds: List<String> = emptyList(),
)

data class ParsedSummary(val summary: String, val priorities: List<String>, val groups: List<AiGroup>, val unknownIds: Int)

/**
 * Валидатор ответа LLM. Два уровня:
 *  1. Структура (Checked.Invalid → повторный запрос с текстом ошибки): строгие типы полей, ссылки на находки пакета,
 *     ограничения размеров; попытка оспорить находку в резюме — тоже ошибка.
 *  2. Очистка содержимого (без повтора, со счётчиками). Перед проверкой текст нормализуется (Unicode NFKC, невидимые символы,
 *     типографские дефисы, percent-encoding), чтобы обход «CVE 2099 9999», полноширинные цифры и URL не проходили:
 *     - CVE/GHSA — только своей находки (её advisoryId и синонимы по справочнику), для группы — её участников;
 *     - файлы и строки — только места своей находки (основное и evidence, ±3 строки: эти строки модель видит во фрагменте);
 *       проверяются оба конца диапазона, переполнение номера — отказ;
 *     - упоминания несуществующих находок вырезаются;
 *     - то, что похоже на секрет, маскируется и на выходе.
 * LLM не меняет набор находок: валидатор не умеет ни добавить, ни убрать находку — только принять или отклонить объяснение.
 */
class ResponseValidator(private val all: List<AiFinding>, private val advisories: Advisories) {

    private val byId = all.associateBy { it.id }

    /** Префиксы идентификаторов находок («f-») — чтобы узнавать упоминания несуществующих находок в тексте. */
    private val idPattern: Regex? = all.mapNotNull { Regex("""^([A-Za-z]+[-_])\d+$""").find(it.id)?.groupValues?.get(1) }.distinct()
        .takeIf { it.isNotEmpty() }?.let { prefixes -> Regex("""(?<![\p{L}\p{N}_-])(?:${prefixes.joinToString("|") { Regex.escape(it) }})\d+(?![\p{L}\p{N}_])""") }

    // ───────────── 1. Структура ─────────────

    fun checkExplain(node: JsonNode, batchIds: Set<String>): Checked<ParsedBatch> {
        val arr = node.path("explanations")
        if (!arr.isArray) return Checked.Invalid(listOf("В корне нужен массив \"explanations\""))
        if (arr.size() > batchIds.size * 2 + 2) return Checked.Invalid(listOf("Слишком много элементов в \"explanations\": ${arr.size()} при ${batchIds.size} находках"))
        val errors = mutableListOf<String>()
        val candidates = mutableListOf<Pair<String, JsonNode>>()
        val unknown = mutableListOf<String>()
        for ((i, el) in arr.withIndex()) {
            if (!el.isObject) { errors += "explanations[$i] должен быть объектом"; continue }
            val idNode = el.path("id")
            if (!idNode.isTextual) { errors += "explanations[$i].id должен быть строкой"; continue }
            typeError(el, "explanation", "string", required = true)?.let { errors += "explanations[$i]: $it" }
            typeError(el, "impact", "string")?.let { errors += "explanations[$i]: $it" }
            typeError(el, "fixSteps", "array<string>")?.let { errors += "explanations[$i]: $it" }
            typeError(el, "fixExample", "string")?.let { errors += "explanations[$i]: $it" }
            val id = idNode.asText()
            if (id !in batchIds) unknown += id else candidates += id to el
        }
        if (errors.isNotEmpty()) return Checked.Invalid(errors.take(10))

        val items = mutableListOf<RawExplanation>()
        val malformed = mutableListOf<String>()
        val disputed = mutableListOf<String>()
        for ((id, group) in candidates.groupBy({ it.first }, { it.second })) {
            // Дубликаты: берём первый содержательный вариант, а не просто первый.
            val el = group.firstOrNull { !it.path("explanation").asText("").isBlank() }
            if (el == null) { malformed += id; continue }
            val explanation = el.path("explanation").asText().trim()
            val impact = el.path("impact").takeIf { it.isTextual }?.asText()?.trim()?.takeIf(String::isNotEmpty)
            val steps = el.path("fixSteps").let { s -> if (s.isArray) s.map { it.asText().trim() }.filter(String::isNotEmpty) else emptyList() }
            if (el.path("dismiss").asBoolean(false) || listOfNotNull(explanation, impact).plus(steps).any { disputes(it) }) { disputed += id; continue }
            items += RawExplanation(
                id = id,
                explanation = explanation.take(1500),
                impact = impact?.take(600),
                fixSteps = steps.take(6).map { it.take(300) },
                fixExample = el.path("fixExample").takeIf { it.isTextual }?.asText()?.trim()?.takeIf(String::isNotEmpty)?.take(3000),
            )
        }
        if (items.isEmpty() && disputed.isEmpty()) {
            return Checked.Invalid(listOf("Нет ни одного объяснения для находок из входа. Допустимые id: ${batchIds.joinToString()}; у каждого элемента нужна непустая строка \"explanation\""))
        }
        return Checked.Ok(ParsedBatch(items, unknown, malformed, disputed))
    }

    fun checkSummary(node: JsonNode): Checked<ParsedSummary> {
        val errors = mutableListOf<String>()
        typeError(node, "summary", "string", required = true)?.let { errors += it }
        typeError(node, "priorities", "array<string>")?.let { errors += it }
        val groupsNode = node.path("groups")
        if (!groupsNode.isMissingNode && !groupsNode.isNull) {
            if (!groupsNode.isArray) errors += "\"groups\" должен быть массивом"
            else {
                if (groupsNode.size() > 10) errors += "Не больше 10 групп"
                groupsNode.forEachIndexed { i, g ->
                    if (!g.isObject) errors += "groups[$i] должен быть объектом"
                    else {
                        typeError(g, "title", "string", required = true)?.let { errors += "groups[$i]: $it" }
                        typeError(g, "ids", "array<string>", required = true)?.let { errors += "groups[$i]: $it" }
                        typeError(g, "story", "string")?.let { errors += "groups[$i]: $it" }
                    }
                }
            }
        }
        if (errors.isNotEmpty()) return Checked.Invalid(errors.take(10))
        val summary = node.path("summary").asText().trim()
        if (summary.isEmpty()) return Checked.Invalid(listOf("Нужна непустая строка \"summary\""))
        val texts = listOf(summary) + groupsNode.flatMap { listOf(it.path("title").asText(""), it.path("story").asText("")) }
        if (texts.any { disputes(it) || DENIAL.containsMatchIn(normalize(it)) }) {
            return Checked.Invalid(listOf("Резюме не может утверждать, что находки безопасны или не требуют исправления: их подтвердили анализаторы. Опиши риски и порядок исправления."))
        }
        var unknown = 0
        val priorities = node.path("priorities").mapNotNull { p -> p.asText().takeIf { it in byId } ?: run { unknown++; null } }.distinct()
        val groups = groupsNode.mapNotNull { g ->
            val ids = g.path("ids").mapNotNull { i -> i.asText().takeIf { it in byId } ?: run { unknown++; null } }.distinct()
            val title = g.path("title").asText("").trim()
            if (ids.size < 2 || title.isEmpty()) null else AiGroup(title.take(200), ids, g.path("story").asText("").trim().take(800))
        }
        return Checked.Ok(ParsedSummary(summary.take(2000), priorities, groups, unknown))
    }

    /** Ошибка типа поля или null. Отсутствующее/null необязательное поле — допустимо. */
    private fun typeError(obj: JsonNode, field: String, type: String, required: Boolean = false): String? {
        val v = obj.path(field)
        if (v.isMissingNode || v.isNull) return if (required) "нет обязательного поля \"$field\"" else null
        return when (type) {
            "string" -> if (v.isTextual) null else "поле \"$field\" должно быть строкой"
            "array<string>" -> if (v.isArray && v.all { it.isTextual }) null else "поле \"$field\" должно быть массивом строк"
            else -> null
        }
    }

    // ───────────── 2. Очистка содержимого ─────────────

    /** Область проверки: какие данные можно упоминать в тексте. */
    class Scope(val findings: List<AiFinding>)

    fun scopeOf(f: AiFinding) = Scope(listOf(f))
    fun scopeOfGroup(ids: List<String>) = Scope(ids.mapNotNull { byId[it] })
    val summaryScope get() = Scope(all)

    /** Текст объяснения/резюме: нормализация → CVE/GHSA → места → ссылки на находки → маскирование секретов. */
    fun sanitize(text: String?, scope: Scope, stats: ValidatorStats): String? {
        if (text == null) return null
        var out = normalize(text)
        out = sanitizeAdvisories(out, scope, stats)
        out = FILE_REF.replace(out) { m -> checkFileRef(m, scope, stats) }
        out = LINE_REF.replace(out) { m ->
            val n = m.groupValues[2].takeIf { it.length <= 7 }?.toIntOrNull()
            if (n != null && lineInScope(null, n, scope)) m.value else { stats.rejectedLocations++; "[место удалено валидатором]" }
        }
        out = sanitizeFindingRefs(out, stats)
        return CodeContext.scrubText(out)
    }

    /**
     * Пример исправления — код. Чистим выдуманные CVE и секреты во всём коде, а места и ссылки на находки — в комментариях
     * (в коде «String::class.java» похоже на имя файла, а места в коде на итог не влияют).
     */
    fun sanitizeCode(code: String?, f: AiFinding, stats: ValidatorStats): String? {
        if (code == null) return null
        val scope = scopeOf(f)
        var out = sanitizeAdvisories(normalize(code), scope, stats)
        out = COMMENT.replace(out) { m ->
            var c = FILE_REF.replace(m.value) { fm -> checkFileRef(fm, scope, stats) }
            c = LINE_REF.replace(c) { lm ->
                val n = lm.groupValues[2].takeIf { it.length <= 7 }?.toIntOrNull()
                if (n != null && lineInScope(null, n, scope)) lm.value else { stats.rejectedLocations++; "[место удалено валидатором]" }
            }
            sanitizeFindingRefs(c, stats)
        }
        return CodeContext.scrubLines(out.split('\n'), config = false, keepComments = true).joinToString("\n")
    }

    /**
     * SCA: шаги модели с номером версии, которой нет среди текущей, рекомендованной и исправленных версий справочника, отбрасываются —
     * целевую версию выбирает справочник, а не модель. Версии других продуктов (TLS 1.3, Java 21) не трогаем.
     */
    fun filterScaSteps(steps: List<String>, f: AiFinding, recommended: String?, stats: ValidatorStats): List<String> {
        if (f.category != "SCA") return steps
        return steps.filter { s ->
            val bad = foreignVersions(normalize(s), f, recommended).isNotEmpty()
            if (bad) stats.rejectedVersions++
            !bad
        }
    }

    /** То же для текста объяснения SCA: чужая версия зависимости заменяется пометкой. */
    fun sanitizeVersions(text: String?, f: AiFinding, recommended: String?, stats: ValidatorStats): String? {
        if (text == null || f.category != "SCA") return text
        val bad = foreignVersions(text, f, recommended).map { it.range }.toSet()
        if (bad.isEmpty()) return text
        val sb = StringBuilder(text)
        bad.sortedByDescending { it.first }.forEach { r -> sb.replace(r.first, r.last + 1, "[версия удалена валидатором]"); stats.rejectedVersions++ }
        return sb.toString()
    }

    /** SCA: пример с версией не из справочника заменяется детерминированной строкой зависимости. */
    fun scaFixExample(code: String?, f: AiFinding, recommended: String?, stats: ValidatorStats): String? {
        if (f.category != "SCA" || code == null) return code
        val allowed = allowedVersions(f, recommended)
        val versions = VERSION.findAll(code).map { it.groupValues[1] }.toList()
        if (versions.all { it in allowed }) return code
        stats.rejectedVersions++
        return recommended?.let { "implementation(\"${f.group}:${f.artifact}:$it\")" }
    }

    private fun allowedVersions(f: AiFinding, recommended: String?) = (listOfNotNull(f.version, recommended) + f.fixedVersions).toSet()

    /** Версии в тексте, которые относятся к обновлению зависимости (рядом «обнов/верси/до/→» или имя артефакта) и не разрешены. */
    private fun foreignVersions(text: String, f: AiFinding, recommended: String?): List<MatchResult> {
        val allowed = allowedVersions(f, recommended)
        return VERSION.findAll(text).filter { m ->
            val v = m.groupValues[1]
            if (v in allowed) return@filter false
            val before = text.substring((m.range.first - 40).coerceAtLeast(0), m.range.first).lowercase()
            if (Regex("""(tls|ssl|java|jdk|jvm|kotlin|spring|boot|gradle|http|cvss|python|node)\s*v?$""").containsMatchIn(before.trimEnd())) return@filter false
            Regex("""(обнов|верси|update|upgrade|bump|→|->|\bдо\b|\bto\b)""").containsMatchIn(before) ||
                (f.artifact != null && before.contains(f.artifact.lowercase()))
        }.toList()
    }

    private fun sanitizeAdvisories(text: String, scope: Scope, stats: ValidatorStats): String {
        val allowed = scope.findings.flatMap { f -> listOfNotNull(f.advisoryId) + (f.advisoryId?.let { advisories.aliasesOf(it) } ?: emptySet()) }
            .map { canonicalAdvisory(it) }.toSet()
        var out = ADVISORY_CVE.replace(text) { m ->
            if ("CVE-${m.groupValues[1]}-${m.groupValues[2]}" in allowed) m.value else { stats.rejectedCves++; "[идентификатор удалён валидатором]" }
        }
        out = ADVISORY_GHSA.replace(out) { m ->
            if ("GHSA-${m.groupValues[1]}-${m.groupValues[2]}-${m.groupValues[3]}".uppercase() in allowed) m.value else { stats.rejectedCves++; "[идентификатор удалён валидатором]" }
        }
        return out
    }

    private fun checkFileRef(m: MatchResult, scope: Scope, stats: ValidatorStats): String {
        val path = m.groupValues[1].replace('\\', '/')
        val base = path.substringAfterLast('/').substringBefore('.')
        // java.sql.Connection, org.json — квалифицированные имена, не файлы
        if ('/' !in path && base.lowercase() in PACKAGE_ROOTS) return m.value
        val start = m.groupValues[2].takeIf { it.isNotEmpty() }
        val end = m.groupValues[3].takeIf { it.isNotEmpty() }
        val file = scopeFiles(scope).firstOrNull { it == path || it.endsWith("/$path") }
        val ok = file != null && listOfNotNull(start, end).all { s -> s.length <= 7 && s.toIntOrNull()?.let { lineInScope(file, it, scope) } == true }
        return if (ok) m.value else { stats.rejectedLocations++; "[место удалено валидатором]" }
    }

    private fun scopeFiles(scope: Scope) = scope.findings.flatMap { f -> listOf(f.path) + f.evidence.map { it.path } }.toSet()

    /** Строка в пределах ±3 от мест находок области; file == null — в любом файле области. */
    private fun lineInScope(file: String?, line: Int, scope: Scope): Boolean = scope.findings.any { c ->
        val ranges = buildList {
            if (c.line != null) add(c.path to (c.line..(c.endLine ?: c.line)))
            c.evidence.forEach { add(it.path to (it.line..(it.endLine ?: it.line))) }
        }
        ranges.any { (p, r) -> (file == null || p == file) && line in (r.first - 3)..(r.last + 3) }
    }

    private fun sanitizeFindingRefs(text: String, stats: ValidatorStats): String =
        idPattern?.replace(text) { m -> if (m.value in byId) m.value else { stats.rejectedFindingRefs++; "[ссылка удалена валидатором]" } } ?: text

    /** Модель оспаривает находку (с учётом отрицания: «это НЕ ложное срабатывание» — не оспаривание). */
    fun disputes(text: String): Boolean {
        val n = normalize(text)
        // омоглифы («лoжное срабатывание» с латинской o): проверяем и исходный текст, и свёртки к кириллице/латинице
        return listOf(n, PromptGuard.toCyrillic(n), PromptGuard.toLatin(n)).any { disputesIn(it) }
    }

    private fun disputesIn(t: String): Boolean {
        fun negated(m: MatchResult) = NEGATION_BEFORE.containsMatchIn(t.substring((m.range.first - 8).coerceAtLeast(0), m.range.first))
        if (DISPUTE.findAll(t).any { !negated(it) }) return true
        return DISPUTE_WEAK.findAll(t).any { m ->
            if (negated(m)) return@any false
            // окно: до 200 символов слева (предыдущее предложение: «обновите до 1.10.0. Эта версия не уязвима») и конец текущего предложения
            val from = (m.range.first - 200).coerceAtLeast(0)
            val to = SENTENCE_END.find(t, m.range.last)?.range?.first ?: t.length
            !FIX_CONTEXT.containsMatchIn(t.substring(from, to))
        }
    }

    companion object {
        /** Нормализация перед проверками: NFKC (полноширинные цифры), невидимые символы, типографские дефисы, percent-encoding. */
        fun normalize(text: String): String {
            var s = Normalizer.normalize(text, Normalizer.Form.NFKC)
            s = s.replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\u00AD]"), "")
            s = s.replace(Regex("[\\u00A0\\u2000-\\u200A\\u202F\\u205F\\u3000]"), " ")
            s = s.replace(Regex("[\\u2010-\\u2015\\u2212]"), "-")
            if ('%' in s) s = Regex("""%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2})*""").replace(s) { m -> runCatching { URLDecoder.decode(m.value, Charsets.UTF_8) }.getOrDefault(m.value) }
            return s
        }

        fun canonicalAdvisory(id: String): String {
            val n = normalize(id).uppercase()
            ADVISORY_CVE.find(n)?.let { return "CVE-${it.groupValues[1]}-${it.groupValues[2]}" }
            ADVISORY_GHSA.find(n)?.let { return "GHSA-${it.groupValues[1]}-${it.groupValues[2]}-${it.groupValues[3]}".uppercase() }
            return n
        }

        private const val SEP = """[\s_\-./:]*"""
        val ADVISORY_CVE = Regex("""(?i)(?<![\p{L}\p{N}])CVE$SEP(\d{4})$SEP(\d{4,7})(?!\d)""")
        val ADVISORY_GHSA = Regex("""(?i)(?<![\p{L}\p{N}])GHSA$SEP([0-9a-z]{4})$SEP([0-9a-z]{4})$SEP([0-9a-z]{4})(?![0-9a-z])""")

        /** Ссылка на файл: путь (Unicode, / или \), расширение (kts раньше kt), необязательная строка: «:12», «:12-14», «#L12», «(12)», «: 12». */
        private val FILE_REF = Regex(
            """(?<![\p{L}\p{N}_./\\-])((?:[\p{L}\p{N}_\-]+[/\\])*[\p{L}\p{N}_\-]+(?:\.[\p{L}\p{N}_\-]+)*\.(?:kts|kt|java|yaml|yml|properties|sql|xml|gradle|json|env|conf))""" +
                """(?![\p{L}\p{N}_]|\.[\p{L}])(?:\s*(?::|#L|\()\s*(\d+)(?:\s*-\s*L?(\d+))?\)?)?""",
        )
        private val LINE_REF = Regex("""(?iu)(?<![\p{L}\p{N}_])(строк[аеиуойм]{0,3}|line|L)\s*(\d+)(?!\d)""")
        private val COMMENT = Regex("""//[^\n]*|/\*[\s\S]*?\*/""")
        private val VERSION = Regex("""(?<![\w.])v?(\d+(?:\.\d+){1,3}|\d{8})(?![\w.]|\.\d)""")
        private val PACKAGE_ROOTS = setOf("java", "javax", "jakarta", "kotlin", "kotlinx", "org", "com", "net", "io", "android", "spring", "sun")

        /** Модель пытается снять находку — это не объяснение: снять находку может только анализатор. */
        private val DISPUTE = Regex(
            """(?iu)ложн\p{L}*\s+срабатыван|не\s+является\s+уязвимост|находк\p{L}*\s+нет|""" +
                """действи\p{L}*\s+не\s+требу|исправлени\p{L}*\s+не\s+требу|исправлять\s+не\s+нужно|не\s+требует\s+исправлени|можно\s+игнорировать|""" +
                """риск\p{L}*\s+отсутству|false\s+positive|not\s+a\s+vulnerability|no\s+action\s+(is\s+)?(needed|required)|""" +
                // следы prompt injection в ответе: модель пересказывает/исполняет указания из данных
                """игнорир\p{L}*\s+(все\s+|предыдущ\p{L}*\s+|эту\s+|данн\p{L}*\s+)*(инструкц|находк|указан|правил|уязвимост)|игнорируй(те)?\b|""" +
                """\bignore\s+(all|this|the|any|these|previous|prior|above)\b|\bdisregard\b|is\s+safe\s+to\s+ignore|mark(ed)?\s+(as\s+)?safe""",
        )
        /**
         * Слабые утверждения («уязвимости нет», «это безопасно», «не уязвим»): честны, когда речь об исправленном варианте
         * («после обновления до 1.10.0 версия не уязвима»), поэтому отклоняются только вне контекста исправления.
         */
        private val DISPUTE_WEAK = Regex(
            """(?iu)(?<![\p{L}])не\s+уязвим|нет\s+уязвимост|уязвимост\p{L}*\s+(здесь\s+)?нет|это\s+безопасно|код\s+безопасен|""" +
                """не\s+представляет\s+(угрозы|опасности)|no\s+vulnerabilit(y|ies)|not\s+vulnerable|is\s+not\s+affected""",
        )
        private val SENTENCE_END = Regex("""[.!?;](\s|$)|\n""")
        /** Контекст исправленного варианта в том же предложении. */
        private val FIX_CONTEXT = Regex(
            """(?iu)после\s+(обновлени|исправлени|замен|применени|внесени)|верси\p{L}*\s+v?\d|\bv?\d+\.\d+|если\s+использ|параметризован|подготовленн|замените|заменить|обновите|обновить|""" +
                """исправленн|при\s+использовании|в\s+новой\s+верси|\bafter\s+(the\s+)?(update|upgrade|fix|patch|change)|if\s+you\s+(use|upgrade|switch)|upgrade|updat|parameteriz|prepared|patched|fixed\s+version""",
        )
        /** «это НЕ ложное срабатывание» — отрицание перед фразой оспаривания. */
        private val NEGATION_BEFORE = Regex("""(?iu)(?<![\p{L}])(не|not)\s+$""")
        /** Резюме, утверждающее, что проблем нет. */
        private val DENIAL = Regex("""(?iu)(критичных\s+)?проблем\s+(не\s+обнаружено|нет)|все\s+находки\s+безопасн|проект\s+безопасен|no\s+(critical\s+)?issues""")
    }
}
