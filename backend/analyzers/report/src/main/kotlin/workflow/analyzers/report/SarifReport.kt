package workflow.analyzers.report

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import workflow.analyzers.secret.SecretRuleCatalog
import java.security.MessageDigest
import java.util.HexFormat
import java.util.Locale

internal fun sarifReport(mapper: ObjectMapper, report: JsonNode): JsonNode {
    val sourceSubdir = report.path("sourceSubdir").textValue()?.let(::relativeSarifUri)
    val findingNodes = if (report.isArray) report else report.path("findings")
    val findings = findingNodes.arrayItems()
        .mapNotNull { sarifFinding(it, sourceSubdir) }
        .sortedWith(compareBy<SarifFinding>({ it.uri }, { it.line }, { it.endLine }, { it.ruleId }, { it.fingerprint })
            .thenByDescending { it.severity })
        .distinctBy { listOf(it.ruleId, it.uri, it.line, it.endLine, it.fingerprint) }
        .toList()

    val catalog = sarifCatalog(report)
    val rules = (catalog.keys + findings.map(SarifFinding::ruleId)).sorted()
    val ruleIndices = rules.withIndex().associate { (index, id) -> id to index }
    val output = mapper.createObjectNode()
        .put("\$schema", "https://json.schemastore.org/sarif-2.1.0.json")
        .put("version", "2.1.0")
    val run = output.putArray("runs").addObject()
    val coverage = report.path("coverage").path("status").textValue()
    if (coverage in setOf("COMPLETE", "PARTIAL", "FAILED")) {
        run.putArray("invocations").addObject().put("executionSuccessful", coverage == "COMPLETE")
        run.putObject("properties").put("coverageStatus", coverage)
    }
    val driver = run.putObject("tool").putObject("driver").put("name", PRODUCT_NAME)
    val ruleNodes = driver.putArray("rules")
    for (ruleId in rules) {
        val category = checkNotNull(ruleCategory(ruleId))
        val metadata = catalog[ruleId] ?: builtInMetadata(ruleId, category)
        val rule = ruleNodes.addObject().put("id", ruleId).put("name", metadata.title)
        rule.putObject("shortDescription").put("text", metadata.title)
        rule.putObject("fullDescription").put("text", metadata.description)
        rule.putObject("defaultConfiguration").put("level", "warning")
        rule.putObject("properties").put("category", category)
            .putArray("tags").add("security").add(category)
    }
    val results = run.putArray("results")
    for (finding in findings) {
        val metadata = catalog[finding.ruleId] ?: builtInMetadata(finding.ruleId, finding.category)
        val result = results.addObject()
            .put("ruleId", finding.ruleId)
            .put("ruleIndex", ruleIndices.getValue(finding.ruleId))
            .put("kind", "fail")
            .put("level", finding.severity?.level ?: "warning")
        val message = finding.advisoryId?.let { "${metadata.title} ($it)" } ?: metadata.title
        result.putObject("message").put("text", message)
        val properties = result.putObject("properties").put("category", finding.category)
        finding.severity?.let { properties.put("severity", it.name) }
        // The upload action computes primaryLocationLineHash from the checked-out source.
        result.putObject("fingerprints").put("codeguardFinding/v1", finding.fingerprint)
        val location = result.putArray("locations").addObject().putObject("physicalLocation")
        location.putObject("artifactLocation").put("uri", finding.uri)
        finding.line?.let { line ->
            val region = location.putObject("region").put("startLine", line)
            finding.endLine?.let { region.put("endLine", it) }
        }
    }
    return output
}

private data class SarifFinding(
    val ruleId: String,
    val category: String,
    val uri: String,
    val line: Int?,
    val endLine: Int?,
    val severity: SarifSeverity?,
    val fingerprint: String,
    val advisoryId: String?,
)

private enum class SarifSeverity(val level: String) {
    INFO("note"),
    LOW("note"),
    MEDIUM("warning"),
    HIGH("error"),
    CRITICAL("error"),
}

private data class RuleMetadata(val title: String, val description: String)

private fun sarifFinding(finding: JsonNode, sourceSubdir: String?): SarifFinding? {
    val category = finding.path("category").textValue()?.takeIf { it in categories } ?: return null
    val path = finding.path("path").textValue()?.let(::relativeSarifUri) ?: return null
    val uri = if (sourceSubdir == null) path else "$sourceSubdir/$path"
    val line = finding.path("line").positiveLine()
    // Older dependency findings can identify the manifest without a declaration line.
    if (line == null && (category != "SCA" || finding.hasNonNull("line"))) return null
    val endLine = line?.let { start ->
        finding.path("endLine").positiveLine()?.takeIf { it > start && it - start <= 14 }
    }
    val severity = SarifSeverity.entries.find { it.name == finding.path("severity").textValue() }
    val ruleId = finding.path("rule").textValue()?.takeIf { ruleCategory(it) == category }
        ?: fallbackRuleId(category, finding.path("class").textValue())
    val advisoryId = if (category == "SCA") {
        finding.path("advisoryId").textValue()?.uppercase(Locale.ROOT)?.takeIf(advisories::matches)
    } else null
    // Secret scanner fingerprints depend on the matched value. Use location-based identity for SECRET.
    val existingFingerprint = finding.path("fingerprint").textValue()
        ?.takeIf { category != "SECRET" && sha256.matches(it) }
    val fingerprint = existingFingerprint ?: hashIdentity(buildList {
        addAll(listOf(ruleId, uri, line?.toString().orEmpty(), endLine?.toString().orEmpty()))
        if (category == "SCA") {
            for (field in listOf("group", "artifact", "version", "advisoryId")) {
                add(finding.path(field).textValue().orEmpty())
            }
        }
    })
    return SarifFinding(ruleId, category, uri, line, endLine, severity, fingerprint, advisoryId)
}

private fun sarifCatalog(report: JsonNode): Map<String, RuleMetadata?> = buildMap {
    val order = compareBy(RuleMetadata::title, RuleMetadata::description)
    for (analyzer in report.path("coverage").path("byAnalyzer")) {
        for (applied in analyzer.path("rulesApplied").arrayItems()) {
            val id = applied.textValue() ?: continue
            if (ruleCategory(id) != null) putIfAbsent(id, null)
        }
        for (descriptor in analyzer.path("rules").arrayItems()) {
            val id = descriptor.path("id").textValue() ?: continue
            val category = ruleCategory(id) ?: continue
            putIfAbsent(id, null)
            if (category == "SECRET") continue
            val title = descriptor.path("title").safeMetadata(255) ?: continue
            val description = descriptor.path("description").safeMetadata(1024) ?: continue
            val metadata = RuleMetadata(title, description)
            val existing = get(id)
            if (existing == null || order.compare(metadata, existing) < 0) put(id, metadata)
        }
    }
}

private val categories = setOf("SECRET", "SAST", "SCA")
private val ruleIds = Regex("(?:secret|sast|sca)\\.[a-z0-9][a-z0-9._-]{0,191}")
private val controls = Regex("[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]")
private val sha256 = Regex("[a-f0-9]{64}")
private val advisories = Regex("CVE-[0-9]{4}-[0-9]{4,}|GHSA-(?:[A-Z0-9]{4}-){2}[A-Z0-9]{4}|POLICY-[A-F0-9]{12,64}")
private val sastRules = mapOf(
    "sql-injection" to ("sast.sql.taint-to-query" to "SQL-инъекция"),
    "tls-verification" to ("sast.tls.trust-all" to "Отключена проверка TLS"),
    "credentialed-cors" to ("sast.cors.any-origin-with-credentials" to "CORS разрешает любой origin с учётными данными"),
    "route-authorization" to ("sast.route.public-sensitive-route" to "Маршрут открыт шире, чем задумано"),
    "object-authorization" to ("sast.idor.read-by-id-without-owner" to "Чтение чужого объекта по идентификатору (IDOR)"),
)
private val sastTitles = sastRules.values.toMap()

private fun ruleCategory(id: String): String? = when {
    !ruleIds.matches(id) -> null
    id == "secret.finding" || SecretRuleCatalog.find(id) != null -> "SECRET"
    id.startsWith("sast.") -> "SAST"
    id.startsWith("sca.") -> "SCA"
    else -> null
}

private fun fallbackRuleId(category: String, findingClass: String?): String = when (category) {
    "SECRET" -> "secret.$findingClass".takeIf { SecretRuleCatalog.find(it) != null } ?: "secret.finding"
    "SAST" -> sastRules[findingClass]?.first
        ?: findingClass?.let { "sast.$it" }?.takeIf { ruleCategory(it) == category }
        ?: "sast.finding"
    else -> "sca.maven-advisory"
}

private fun builtInMetadata(id: String, category: String): RuleMetadata = when (category) {
    "SECRET" -> SecretRuleCatalog.find(id)?.let { RuleMetadata(it.title, it.description) }
        ?: RuleMetadata("Секрет в исходниках", "Проверяет, содержится ли секрет в исходном файле.")
    "SAST" -> {
        val title = sastTitles[id] ?: "Находка статического анализа"
        RuleMetadata(title, "$title. Проверьте указанное место в исходном файле.")
    }
    else -> RuleMetadata("Уязвимая или запрещённая зависимость", "Проверяет установленную версию зависимости.")
}

private fun JsonNode.positiveLine(): Int? = takeIf { isIntegralNumber && canConvertToInt() }
    ?.intValue()?.takeIf { it > 0 }

private fun JsonNode.arrayItems(): Sequence<JsonNode> = if (isArray) elements().asSequence() else emptySequence()

private fun JsonNode.safeMetadata(limit: Int): String? = textValue()?.trim()
    ?.takeIf { it.isNotEmpty() && it.length <= limit && !controls.containsMatchIn(it) }

private fun relativeSarifUri(value: String): String? {
    val path = value.replace('\\', '/')
    if (path.startsWith('/') || path.endsWith('/') || ':' in path || controls.containsMatchIn(path)) return null
    val parts = path.split('/')
    if (parts.any { it.trimEnd(' ') == ".." }) return null
    val normalized = parts.filter { it.isNotEmpty() && it != "." }.joinToString("/")
    if (normalized.isBlank() || !Charsets.UTF_8.newEncoder().canEncode(normalized)) return null
    return buildString {
        val hex = "0123456789ABCDEF"
        for (byte in normalized.toByteArray(Charsets.UTF_8)) {
            val unsigned = byte.toInt() and 0xff
            val char = unsigned.toChar()
            when (char) {
                in 'A'..'Z', in 'a'..'z', in '0'..'9', '-', '.', '_', '~', '/' -> append(char)
                else -> append('%').append(hex[unsigned ushr 4]).append(hex[unsigned and 0xf])
            }
        }
    }
}

private fun hashIdentity(fields: List<String>): String {
    val bytes = fields.joinToString("") { "${it.length}:$it" }.toByteArray(Charsets.UTF_8)
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
}
