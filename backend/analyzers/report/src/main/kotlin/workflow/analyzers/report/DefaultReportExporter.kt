package workflow.analyzers.report

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.springframework.stereotype.Component
import workflow.engine.ReportExporter
import workflow.engine.ruCount

@Component
class DefaultReportExporter(private val mapper: ObjectMapper) : ReportExporter {
    private val aliases: Map<Triple<String, String, String>, String> by lazy {
        val catalog = javaClass.getResourceAsStream("/sca/vulnerabilities.json")
            ?.use { mapper.readTree(it) }
        buildMap {
            for (advisory in catalog?.path("vulnerabilities")?.elements()?.asSequence() ?: emptySequence()) {
                val group = advisory.text("group") ?: continue
                val artifact = advisory.text("artifact") ?: continue
                val id = advisory.text("id")?.let(::advisorySpelling) ?: continue
                val otherIds = advisory.path("aliases").mapNotNull {
                    it.textValue()?.let(::advisorySpelling)
                }
                val canonical = (otherIds + id).filter { cveId.matches(it) }.minOrNull() ?: id
                for (alias in otherIds + id) put(Triple(group, artifact, alias), canonical)
            }
        }
    }

    override fun json(report: JsonNode): JsonNode = mapper.createObjectNode().apply {
        val findings = putArray("findings")
        normalize(report).forEach { findings.add(it.fields) }
    }

    override fun sarif(report: JsonNode): JsonNode = sarifReport(mapper, report)

    override fun pdf(report: JsonNode, meta: JsonNode?): ByteArray = PdfReport(report, meta).render()

    override fun markdown(report: JsonNode): String = buildString {
        val findings = normalize(report)
        val coverage = report.path("coverage")
        val analyzers = coverage.path("byAnalyzer").fields().asSequence().sortedBy { it.key }.toList()
        val status = coverageStatus(coverage)
        appendLine(when (status) {
            "FAILED" -> "# Отчёт проверки — FAILED. Анализ завершился ошибкой."
            "PARTIAL" -> "# Отчёт проверки — PARTIAL. Анализ неполный."
            else -> "# Отчёт проверки"
        })
        appendLine()
        appendLine("## Находки")
        appendLine()
        when {
            findings.isNotEmpty() -> appendLine("Найдено: ${findings.size}.")
            status == "COMPLETE" -> appendLine("Находок нет.")
            else -> appendLine("Находки не зарегистрированы. Итог проверки неизвестен.")
        }
        findings.forEach { appendFinding(it) }

        val languages = report.path("languages")
        if (languages.isArray && languages.size() > 0) {
            appendLine()
            appendLine("## Языки проекта")
            appendLine()
            for (language in languages) {
                val name = language.text("name") ?: continue
                val files = language.path("files").nonnegativeInt() ?: continue
                val note = language.text("note")?.let { " — ${inline(it)}" }.orEmpty()
                appendLine("- ${inline(name)}: ${ruCount(files, "файл", "файла", "файлов")}$note")
            }
        }

        appendLine()
        appendLine("## Покрытие — $status")
        for ((name, analyzer) in analyzers) {
            appendLine()
            appendLine("### ${inline(name)} — ${coverageStatus(analyzer)}")
            appendLine()
            val analyzed = analyzer.path("filesAnalyzed").nonnegativeInt()?.toString() ?: "неизвестно"
            appendLine("Разобрано файлов: $analyzed.")
            val dependencies = analyzer.path("dependencyCoverage")
            val checked = dependencies.path("checked").nonnegativeInt()
            val withoutAdvisories = dependencies.path("withoutAdvisories").nonnegativeInt()
            val unresolvedVersion = dependencies.path("unresolvedVersion").nonnegativeInt()
            if (checked != null && withoutAdvisories != null && unresolvedVersion != null) {
                appendLine("Объявления зависимостей — сверено со справочником: $checked, " +
                    "известна версия, но нет записей: $withoutAdvisories, " +
                    "версия не установлена или не поддерживается: $unresolvedVersion.")
            }
            analyzer.path("advisoryCount").nonnegativeInt()?.let { appendLine("Записей в справочнике SCA после объединения: $it.") }
            for (source in analyzer.path("advisorySources")) {
                val path = source.text("path")?.let { relativePath(it) ?: it.replace('\\', '/').substringAfterLast('/') }?.takeIf(String::isNotBlank) ?: continue
                val records = source.path("records").nonnegativeInt() ?: continue
                val origin = when (source.text("source")) {
                    "builtin" -> "встроенный"
                    "project" -> "из проекта"
                    else -> continue
                }
                val snapshot = source.text("snapshotDate")?.let { ", дата снимка ${inline(it)}" }.orEmpty()
                appendLine("- Справочник ${inline(path)} ($origin): $records$snapshot")
            }
            for (bom in analyzer.path("springBootBoms")) {
                val release = bom.text("release") ?: continue
                val path = bom.text("path")?.let(::relativePath) ?: continue
                val line = bom.path("line").nonnegativeInt()?.takeIf { it > 0 } ?: continue
                appendLine("- Spring Boot BOM ${inline(release)} — ${inline(path)}:$line")
            }
            for (rule in analyzer.path("rules")) {
                val id = rule.text("id") ?: continue
                val title = rule.text("title") ?: continue
                val description = rule.text("description") ?: continue
                appendLine("- ${inline(title)} (${inline(id)}) — ${inline(description)}")
            }
            appendLocations("Пропущено файлов", analyzer.path("filesSkipped"))
            appendLocations("Не установлено", analyzer.path("unresolved"), "kind", "subject")
        }

        val ai = report.path("ai")
        val aiStatus = ai.text("status")?.takeIf { it in aiStatuses } ?: "NOT_RECEIVED"
        appendLine()
        appendLine("## AI — $aiStatus")
        ai.text("model")?.let { appendLine("Модель: ${inline(it)}") }
        val validator = ai.path("validator")
        for (key in validatorCounters) {
            validator.path(key).nonnegativeInt()?.let { appendLine("- $key: $it") }
        }

        appendLine()
        appendLine("<details>")
        appendLine("<summary>Отклонённые безопасные места</summary>")
        appendLine()
        val dismissed = analyzers.flatMap { (name, analyzer) ->
            coverageLocations(analyzer.path("dismissed"), "rule").map { "${inline(name)} · $it" }
        }
        if (dismissed.isEmpty()) appendLine("Нет записей.")
        else dismissed.forEach { appendLine("- $it") }
        appendLine()
        appendLine("</details>")
    }

    private fun normalize(report: JsonNode): List<ExportedFinding> {
        val findings = if (report.isArray) report else report.path("findings")
        if (!findings.isArray) return emptyList()
        return findings.elements().asSequence().mapNotNull(::project)
            .sortedWith(findingOrder)
            .distinctBy { it.key }
            .toList()
    }

    private fun project(source: JsonNode): ExportedFinding? {
        val category = source.text("category")?.takeIf { it in categories } ?: return null
        val path = source.text("path")?.let(::relativePath) ?: return null
        val fields = mapper.createObjectNode().put("category", category).put("path", path)
        val key = if (category == "SCA") {
            val group = source.text("group") ?: return null
            val artifact = source.text("artifact") ?: return null
            val version = source.text("version") ?: return null
            val advisory = source.text("advisoryId")?.let(::advisorySpelling) ?: return null
            val canonical = aliases[Triple(group, artifact, advisory)] ?: advisory
            fields.put("group", group).put("artifact", artifact).put("version", version).put("advisoryId", canonical)
            FindingKey(category, path, names = listOf(group, artifact, version, canonical))
        } else {
            val kind = source.text("class") ?: return null
            val line = source.path("line").nonnegativeInt()?.takeIf { it > 0 } ?: return null
            val end = if (source.hasNonNull("endLine")) source.path("endLine").nonnegativeInt() ?: return null else line
            if (end < line || end.toLong() - line > 14) return null
            fields.put("class", kind).put("line", line)
            if (end != line) fields.put("endLine", end)
            FindingKey(category, path, line, end, listOf(kind))
        }

        val secret = category == "SECRET"
        val secretTitle = secretTitles[fields.path("class").textValue()] ?: "Встроенный секрет"
        source.text("severity")?.takeIf { it in severities }?.let { fields.put("severity", it) }
        // Secret findings use generated wording so source snippets cannot enter either export.
        source.text("description")?.let { fields.put("description", if (secret) secretTitle else it) }
        source.text("remediation")?.let { fields.put("remediation", if (secret) secretRemediation else it) }
        val title = if (secret) secretTitle else source.text("title") ?: key.names.last()
        return ExportedFinding(key, fields, title)
    }

    private fun StringBuilder.appendFinding(finding: ExportedFinding) {
        val fields = finding.fields
        val key = finding.key
        appendLine()
        appendLine("### ${key.category} · ${inline(finding.title)}")
        appendLine()
        val location = when {
            key.line == 0 -> inline(key.path)
            key.line == key.endLine -> "${inline(key.path)}:${key.line}"
            else -> "${inline(key.path)}:${key.line}–${key.endLine}"
        }
        appendLine("- Место: $location")
        if (key.category == "SCA") {
            appendLine("- Зависимость: ${inline(key.names.take(3).joinToString(":"))}")
            appendLine("- Идентификатор: ${inline(key.names.last())}")
        }
        appendLine("- Критичность: ${fields.text("severity") ?: "не указана"}")
        if (key.category == "SECRET") appendLine("- Значение: `****`")
        appendLine("- Описание: ${inline(fields.text("description") ?: finding.title)}")
        val remediation = fields.text("remediation") ?: if (key.category == "SECRET") secretRemediation else "не указана"
        appendLine("- Рекомендация: ${inline(remediation)}")
    }

    private fun StringBuilder.appendLocations(title: String, locations: JsonNode, vararg labels: String) {
        val items = coverageLocations(locations, *labels)
        val count = if (locations.isArray) items.size.toString() else "неизвестно"
        appendLine("$title: $count.")
        items.forEach { appendLine("- $it") }
    }

    private fun coverageLocations(items: JsonNode, vararg labels: String): List<String> = items.elements().asSequence()
        .filter { it.isObject }
        .mapNotNull { item ->
            val path = item.text("path")?.let(::relativePath) ?: return@mapNotNull null
            val line = item.path("line").nonnegativeInt()?.takeIf { it > 0 }
            val label = labels.mapNotNull { item.text(it) }.joinToString(" · ", transform = ::inline)
            val reason = item.text("reason")?.let(::inline) ?: "причина не указана"
            CoverageLocation(path, line ?: 0, label, reason)
        }
        .distinct()
        .sortedWith(compareBy(CoverageLocation::path, CoverageLocation::line, CoverageLocation::label, CoverageLocation::reason))
        .map { item ->
            val location = inline(item.path) + if (item.line > 0) ":${item.line}" else ""
            val label = if (item.label.isEmpty()) "" else " · ${item.label}"
            "$location$label — ${item.reason}"
        }
        .toList()

    private data class CoverageLocation(val path: String, val line: Int, val label: String, val reason: String)
    private data class ExportedFinding(val key: FindingKey, val fields: ObjectNode, val title: String)
    private data class FindingKey(
        val category: String,
        val path: String,
        val line: Int = 0,
        val endLine: Int = 0,
        val names: List<String>,
    )

    private companion object {
        val categories = listOf("SECRET", "SAST", "SCA")
        val severities = setOf("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO")
        val coverageStatuses = setOf("COMPLETE", "PARTIAL", "FAILED")
        val aiStatuses = setOf("OK", "PARTIAL", "NOT_RECEIVED")
        val validatorCounters = listOf("responses", "schemaFailures", "rejectedFindingRefs", "rejectedCves")
        val cveId = Regex("CVE-[0-9]{4}-[0-9]{4,}")
        val ghsaId = Regex("GHSA-(?:[a-z0-9]{4}-){2}[a-z0-9]{4}")
        val controls = Regex("[\\p{Cc}\\p{Zl}\\p{Zp}]+")
        val secretTitles = mapOf(
            "password" to "Пароль в исходниках",
            "api-key" to "Ключ API в исходниках",
            "configuration-token" to "Секрет в конфигурации",
            "secret-fallback" to "Секрет в значении по умолчанию",
            "recoverable-token" to "Секрет восстанавливается из констант",
            "high-entropy" to "Строка похожа на ключ (высокая энтропия)",
            "custom-regex" to "Совпадение с пользовательским правилом",
        )
        const val secretRemediation = "Перенесите значение в переменную окружения или хранилище секретов. Если значение использовалось, замените его."

        val findingOrder = compareBy<ExportedFinding>(
            { categories.indexOf(it.key.category) }, { it.key.path }, { it.key.line }, { it.key.endLine },
            { it.key.names[0] }, { it.key.names.getOrNull(1) }, { it.key.names.getOrNull(2) },
            { it.key.names.getOrNull(3) },
        ).thenByDescending { it.fields.size() }
            .thenBy { it.fields.toString() }
            .thenBy { it.title }

        fun JsonNode.text(name: String): String? = path(name).textValue()?.takeIf(String::isNotBlank)

        fun JsonNode.nonnegativeInt(): Int? =
            takeIf { it.isIntegralNumber && it.canConvertToInt() }?.intValue()?.takeIf { it >= 0 }

        fun coverageStatus(node: JsonNode): String = node.text("status")?.takeIf { it in coverageStatuses } ?: "PARTIAL"

        fun relativePath(value: String): String? {
            val path = value.replace('\\', '/')
            if (path.startsWith('/') || ':' in path || controls.containsMatchIn(path)) return null
            val parts = path.split('/')
            if (".." in parts) return null
            return parts.filter { it.isNotEmpty() && it != "." }.joinToString("/").takeIf(String::isNotBlank)
        }

        fun advisorySpelling(value: String): String = value.trim().let { id ->
            val cve = id.uppercase()
            val ghsa = "GHSA-" + id.drop(5).lowercase()
            when {
                cveId.matches(cve) -> cve
                id.startsWith("GHSA-", ignoreCase = true) && ghsaId.matches(ghsa) -> ghsa
                else -> id
            }
        }

        fun inline(value: String): String = buildString {
            for (character in controls.replace(value, " ")) {
                when (character) {
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '&' -> append("&amp;")
                    '\\', '`', '*', '_', '[', ']', '|' -> append('\\').append(character)
                    else -> append(character)
                }
            }
        }
    }
}
