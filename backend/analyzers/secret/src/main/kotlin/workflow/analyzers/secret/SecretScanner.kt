package workflow.analyzers.secret

import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceFile
import codeguard.analyzers.model.SourceType
import codeguard.analyzers.model.isVersionCatalog
import java.security.MessageDigest
import java.util.HexFormat

internal class SecretCandidate(
    val kind: String,
    val value: String,
    val location: Location,
    val evidence: List<Location> = listOf(location),
    /** Найден в тестовом коде: находка остаётся, но с низкой критичностью и пометкой (совет автор набора 21.11). */
    val testSource: Boolean = false,
)

internal data class SecretDismissal(val rule: String, val location: Location, val reason: String)
internal data class SecretRuleResult(val candidates: List<SecretCandidate>, val dismissed: List<SecretDismissal>)

private val camelBoundary = Regex("(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
private val separators = Regex("[^a-z0-9]+")
private val metadataWords = setOf("name", "variable", "property", "header", "prefix", "suffix", "url", "file", "path", "alias", "id", "type", "length", "size", "algorithm", "provider", "store", "version", "ref", "count")
private val passwordWords = setOf("password", "passwd", "pwd")
private val tokenWords = setOf("secret", "token", "authorization", "bearer", "jwt", "secretkey")
private val cryptoWords = setOf("aes", "jwt", "signing", "encryption", "secret")

internal fun secretKind(name: String): String? {
    val words = name.replace(camelBoundary, "-").lowercase().split(separators).filter(String::isNotEmpty)
    val last = words.lastOrNull() ?: return null
    if (last in metadataWords) return null
    if (words.size > 2 && words[0] == "access" && words[1] == "control") return null
    val packed = words.joinToString("")
    return when {
        words.any(passwordWords::contains) || last == "pass" || packed.endsWith("password") ||
            last == "passphrase" || last == "credentials" || last == "credential" -> "password"
        packed.endsWith("apikey") || packed.endsWith("accesskey") -> "api-key"
        last in tokenWords || packed.endsWith("clientsecret") || packed.endsWith("accesstoken") ||
            (last == "key" && words.any(cryptoWords::contains)) ||
            packed.endsWith("masterkey") || packed.endsWith("privatekey") || packed.endsWith("hmackey") -> "configuration-token"
        else -> null
    }
}

private val placeholder = Regex("(?i)^(?:your[\\s_-].*|<[^<>]+>|\\{\\{[^}]+}}|\\*+|changeme|change[_-]?me|replace[_-]?me|placeholder|example|dummy|null|none|true|false|x{3,}|redacted|masked|hidden|todo|tbd|[.]{3,}|[$]\\{[A-Za-z_][A-Za-z0-9_.-]*})$")

internal fun isPlaceholder(value: String): Boolean =
    value.trim().let { it.isEmpty() || placeholder.matches(it) }

private val testDirectories = setOf("test", "tests", "testfixtures", "integrationtest", "androidtest")

private fun isSecretTestSource(path: String): Boolean {
    val parts = path.lowercase().split('/')
    val name = parts.last()
    return parts.dropLast(1).any { it in testDirectories } || name.endsWith("test.kt") || name.endsWith("tests.kt")
}

internal fun isBuiltInSecretScanExcluded(path: String): Boolean {
    val name = path.substringAfterLast('/').lowercase()
    return name.startsWith("readme") ||
        name.endsWith(".md") || name.endsWith(".markdown") || name == ".env.example" || name == ".env.sample"
}

internal fun isCustomSecretScanExcluded(path: String): Boolean =
    isSecretTestSource(path) || isBuiltInSecretScanExcluded(path)

private data class SecretClass(val severity: String, val title: String)

private val classes = linkedMapOf(
    "password" to SecretClass("HIGH", "Пароль в исходниках"),
    "api-key" to SecretClass("MEDIUM", "Ключ API в исходниках"),
    "configuration-token" to SecretClass("HIGH", "Секрет в конфигурации"),
    "secret-fallback" to SecretClass("LOW", "Секрет в значении по умолчанию"),
    "recoverable-token" to SecretClass("MEDIUM", "Секрет восстанавливается из констант"),
    "high-entropy" to SecretClass("MEDIUM", "Строка похожа на ключ (высокая энтропия)"),
    "custom-regex" to SecretClass("MEDIUM", "Совпадение с пользовательским правилом"),
)
internal val builtInSecretRules = classes.keys.filter { it != "custom-regex" }.map { "secret.$it" }
private val secretSourceTypes = setOf(SourceType.KOTLIN, SourceType.KOTLIN_SCRIPT, SourceType.YAML, SourceType.PROPERTIES, SourceType.ENV, SourceType.XML, SourceType.PEM, SourceType.DOCKERFILE, SourceType.JSON, SourceType.SQL)
private val customSecretExcludedTypes = setOf(SourceType.MARKDOWN, SourceType.OTHER, SourceType.ADVISORY_DATABASE)

internal fun SourceFile.isBuiltInSecretSource(): Boolean = type in secretSourceTypes || isVersionCatalog(path)

internal fun SourceFile.isCustomSecretSource(): Boolean = type !in customSecretExcludedTypes

private val severityOrder = listOf("LOW", "MEDIUM", "HIGH", "CRITICAL")

internal fun scanBuiltInSecrets(model: ProjectModel): SecretRuleResult {
    val kotlin = scanKotlinSecrets(model)
    val config = scanConfigSecrets(model)
    val named = kotlin.candidates + config.candidates + scanPemFiles(model) + scanSqlSecrets(model) + scanOtherTextSecrets(model) +
        scanForeignSourceSecrets(model)
    val known = named.flatMap { it.evidence + it.location } + (kotlin.dismissed + config.dismissed).map { it.location }
    val (excluded, candidates) = (named + scanEntropySecrets(model, known))
        .partition { isBuiltInSecretScanExcluded(it.location.path) }
    val excludedFiles = model.files.filter {
        (it.isBuiltInSecretSource() || it.type == SourceType.MARKDOWN) && isBuiltInSecretScanExcluded(it.path)
    }.map { SecretDismissal("secret.scope", Location(it.path, 1), "excluded-source") }
    val excludedCandidates = excluded.map { SecretDismissal("secret." + it.kind, it.location, "excluded-source") }
    return SecretRuleResult(
        candidates.map { candidate ->
            if (isSecretTestSource(candidate.location.path)) {
                SecretCandidate(candidate.kind, candidate.value, candidate.location, candidate.evidence, testSource = true)
            } else candidate
        },
        (kotlin.dismissed + config.dismissed + excludedFiles + excludedCandidates).distinct(),
    )
}

/** Имя, которое не доказывает секрет само по себе: нужна проверка значения (`partnerKey = "k9..."`). */
internal class WeakSecretName(val kind: String, val minLength: Int)

private val valueSuffixes = setOf("value", "string", "str", "text", "literal", "val", "raw", "plain")
private val pluralNames = mapOf(
    "keys" to "key", "tokens" to "token", "secrets" to "secret", "passwords" to "password",
    "apikeys" to "apikey", "credentials" to "credential",
)
private val nonSecretKeyWords = setOf(
    "cache", "primary", "sort", "message", "partition", "routing", "idempotency", "i18n", "translation", "foreign",
    "lookup", "dedup", "dedupe", "shard", "map", "enum", "label", "bundle", "resource", "locale", "search", "unique",
    "composite", "natural", "hash", "row", "column", "index", "order", "session", "correlation", "trace", "request",
    "shortcut", "group", "join", "field", "property", "env", "setting", "param", "query", "cookie", "attribute", "bean",
    "json", "redis", "kafka", "s3", "storage", "object", "lang", "language", "i18", "bucket", "queue", "topic",
    "config", "alias", "algorithm", "hotkey", "sorting", "pagination", "page", "cursor", "etag", "version",
)

/**
 * Имя без явного слова про секрет: `partnerKey`, `licenseKey`, `authKey`, `tokenValue`, `apiKeys`.
 * Возвращает класс и минимальную длину значения; сам по себе вердикт не выносит, значение проверяет [looksLikeSecretValue].
 */
internal fun weakSecretName(name: String): WeakSecretName? {
    var words = name.replace(camelBoundary, "-").lowercase().split(separators).filter(String::isNotEmpty)
    if (words.isEmpty()) return null
    if (words.size > 1 && words.last() in valueSuffixes) words = words.dropLast(1)
    pluralNames[words.last()]?.let { words = words.dropLast(1) + it }
    val last = words.last()
    if (last in metadataWords) return null
    secretKind(words.joinToString("-"))?.let { return WeakSecretName(it, 8) }
    if (words.any { it in nonSecretKeyWords }) return null
    return when {
        last == "key" && words.size >= 2 -> WeakSecretName("api-key", 8)
        last == "auth" || last == "bearer" -> WeakSecretName("configuration-token", 8)
        else -> null
    }
}

private val dottedProperty = Regex("^[a-z0-9]+(?:\\.[a-z0-9_-]+)+$")

/** Значение похоже на секрет: без пробелов, буквы и цифры, не заглушка, не адрес, не путь, не слова через разделитель. */
internal fun looksLikeSecretValue(raw: String, minLength: Int): Boolean {
    val value = raw.trim()
    if (value.length < minLength || value.length > 512) return false
    if (value.any(Char::isWhitespace) || isPlaceholder(value)) return false
    if ("://" in value || "\${" in value || value.startsWith("#{") || value.startsWith("/") || value.startsWith(".")) return false
    if (value.none(Char::isLetter) || value.none(Char::isDigit)) return false
    if (dottedProperty.matches(value)) return false
    val segments = value.split('-', '_', '.', ':').filter(String::isNotEmpty)
    if (segments.size > 1 && segments.count { s -> s.length >= 3 && s.all(Char::isLetter) } >= 2) return false
    return true
}

/** Слабое имя + значение, похожее на секрет → класс находки. */
internal fun weakSecretKind(name: String?, value: String?): String? {
    if (name == null || value == null) return null
    val weak = weakSecretName(name) ?: return null
    return weak.kind.takeIf { looksLikeSecretValue(value, weak.minLength) }
}

private val kindPriority =listOf("password", "api-key", "secret-fallback", "recoverable-token", "configuration-token", "high-entropy")

/**
 * Одна строка — один секрет: встроенные находки разных классов с общим (путь, начальная строка) сводятся к одной
 * по приоритету классов, доказательства отброшенных переносятся в оставшуюся. Пользовательские правила не затрагиваются.
 */
internal fun dedupeByLine(sorted: List<SecretCandidate>): List<SecretCandidate> {
    val (custom, builtIn) = sorted.partition { it.kind == "custom-regex" }
    val merged = builtIn.groupBy { it.location.path to it.location.line }.values.map { group ->
        val keep = group.minByOrNull { kindPriority.indexOf(it.kind).let { i -> if (i < 0) kindPriority.size else i } }!!
        if (group.size == 1) keep
        else SecretCandidate(keep.kind, keep.value, keep.location, (keep.evidence + group.flatMap { it.evidence + it.location }).distinct(), keep.testSource)
    }
    return (merged + custom).sortedWith(compareBy({ it.location.path }, { it.location.line }, { it.location.endLine ?: it.location.line }, { it.kind }))
}

internal fun secretFindings(
    model: ProjectModel,
    candidates: List<SecretCandidate>,
    minimumSeverity: String = "LOW",
): ArrayNode {
    val sourceHashes = model.files.associate { it.path to it.sha256 }
    val output = JsonNodeFactory.instance.arrayNode()
    dedupeByLine(candidates.sortedWith(compareBy({ it.location.path }, { it.location.line }, { it.location.endLine ?: it.location.line }, { it.kind }))
        .distinctBy { Triple(it.kind, it.location.path, it.location.line to (it.location.endLine ?: it.location.line)) })
        .forEach { candidate ->
            val base = classes.getValue(candidate.kind)
            val meta = if (candidate.testSource) SecretClass("LOW", base.title + " (тестовый код)") else base
            if (severityOrder.indexOf(meta.severity) < severityOrder.indexOf(minimumSeverity)) return@forEach
            val location = candidate.location
            val end = (location.endLine ?: location.line).coerceIn(location.line, location.line + 14)
            val fields = listOf(
                "SECRET", candidate.kind, location.path, location.line.toString(), end.toString(),
                candidate.value.trim(), sourceHashes.getValue(location.path),
            )
            val fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(fields.joinToString("") { it.length.toString() + ":" + it }.toByteArray(Charsets.UTF_8)))
            val finding = output.addObject()
                .put("id", "secret-$fingerprint")
                .put("fingerprint", fingerprint)
                .put("category", "SECRET")
                .put("class", candidate.kind)
                .put("path", location.path)
                .put("line", location.line)
                .put("severity", meta.severity)
                .put("rule", "secret." + candidate.kind)
                .put("title", meta.title)
                .put("description", meta.title)
                .put("remediation", if (candidate.testSource)
                    "Вынесите значение из тестового кода в переменные окружения тестов или фиктивные данные. Если это рабочий секрет, замените его."
                else "Перенесите значение в переменную окружения или хранилище секретов. Если значение использовалось, замените его.")
                .put("secretMasked", "****")
            if (end > location.line) finding.put("endLine", end)
            val evidence = finding.putArray("evidence")
            for (source in candidate.evidence.ifEmpty { listOf(location) }.distinct()) {
                val item = evidence.addObject().put("path", source.path).put("line", source.line)
                source.endLine?.takeIf { it > source.line }?.let { item.put("endLine", it) }
            }
        }
    return output
}
