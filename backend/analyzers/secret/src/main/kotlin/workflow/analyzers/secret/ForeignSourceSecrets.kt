package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceFile
import codeguard.analyzers.model.SourceType
import codeguard.analyzers.model.isForeignText

/*
 * Исходники на любом языке (Java, C/C++, Python, Go, JS/TS, C#, PHP, Rust, Ruby…) и прочие текстовые файлы,
 * которые не разбирает модель: ищем секреты по общим правилам, не зависящим от синтаксиса языка.
 *  - известные форматы ключей (AWS, GitHub, Slack, Google, Stripe, Telegram) и пароль в URL в любой строке;
 *  - приватные ключи PEM;
 *  - присваивание строкового литерала переменной/полю/ключу словаря с именем про пароль или секрет;
 *  - случайная строка высокой энтропии в литерале рядом со словами password/token/secret/key.
 * Строки длиннее MAX_LINE (минифицированный код) проверяем только по известным форматам.
 */

private const val MAX_LINE = 4000

internal fun SourceFile.isForeignSecretSource(): Boolean =
    text.isNotEmpty() && !isOtherTextSource() &&
        ((type == SourceType.OTHER && isForeignText(path)) || (type == SourceType.TOML && !isBuiltInSecretSource()))

private val doubleQuoted = Regex(""""([^"\\\n]*+(?:\\.[^"\\\n]*+)*+)"""")
private val singleQuoted = Regex("""'([^'\\\n]*+(?:\\.[^'\\\n]*+)*+)'""")
private val backtick = Regex("""`([^`\\\n]*+(?:\\.[^`\\\n]*+)*+)`""")
private val literalAssignment = Regex(
    """["']?([A-Za-z_][A-Za-z0-9_.-]{0,60})["']?\s*(?::=|=>|->|[:=])\s*(["'`])([^"'`\\\n]{1,300})\2""",
)
private val defineAssignment = Regex("""#\s*define\s+([A-Za-z_]\w{0,60})\s+(["'])([^"'\\\n]{1,300})\2""")
private val callAssignment = Regex("""\b([A-Za-z_]\w{0,60})\s*\(\s*(["'])([^"'\\\n]{1,300})\2\s*\)""")
private val privateKeyBegin = Regex("""-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----""")
private val allCapsName = Regex("""[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+""")
private val formatPlaceholder = Regex("""%[sdvf@]|%\(|\{\d*}|<%|\$\{|\{\{|\$[A-Za-z_(]""")
private val hashWords = Regex("""(?i)sha\d*|md5|hash|checksum|digest|integrity|commit|etag|fingerprint|uuid|guid|version""")
private val telling =Regex("""(?i)pass|pwd|secret|token|key|auth|credential""")
private val notSecretWords = setOf("password", "passwd", "secret", "token", "apikey", "api_key", "username", "string", "text", "email")

private fun literalsOf(line: String): List<String> =
    (doubleQuoted.findAll(line) + singleQuoted.findAll(line) + backtick.findAll(line)).map { it.groupValues[1] }.toList()

private fun usableLiteral(value: String): Boolean =
    value.length >= 4 && value.none(Char::isWhitespace) && !isPlaceholder(value) &&
        !formatPlaceholder.containsMatchIn(value) && !allCapsName.matches(value)

internal fun scanForeignSourceSecrets(model: ProjectModel): List<SecretCandidate> = buildList {
    for (file in model.files.filter { it.isForeignSecretSource() }) {
        file.text.lineSequence().forEachIndexed { index, rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty()) return@forEachIndexed
            val location = Location(file.path, index + 1)
            fun accept(kind: String, value: String) { add(SecretCandidate(kind, value, location)) }

            knownTokenShape(line)?.let { (kind, secret) -> accept(kind, secret); return@forEachIndexed }
            if (line.length > MAX_LINE) return@forEachIndexed
            privateKeyBegin.find(line)?.let { accept("configuration-token", it.value); return@forEachIndexed }
            val literals = literalsOf(line)
            for (literal in literals) {
                embeddedCredential(literal)?.let { (kind, secret) -> accept(kind, secret); return@forEachIndexed }
            }
            val matches = (literalAssignment.findAll(line) + defineAssignment.findAll(line)).map { it to true } +
                callAssignment.findAll(line).map { it to false }
            for ((match, weakAllowed) in matches) {
                val name = match.groupValues[1]
                val value = match.groupValues[3]
                if (!usableLiteral(value) || value.equals(name, ignoreCase = true) || value.lowercase() in notSecretWords) continue
                val kind = secretKind(name) ?: (if (weakAllowed) weakSecretKind(name, value) else null) ?: continue
                // `token: 'keyword'` в литерале объекта (подсветка, схемы) — не секрет: нужно значение, похожее на секрет.
                val rest = match.value.removePrefix("\"").removePrefix("'").drop(name.length).trimStart('"', '\'', ' ')
                val objectKey = rest.startsWith(":") && !rest.startsWith(":=")
                if (objectKey && kind != "password" && !looksLikeSecretValue(value, 6)) continue
                accept(kind, value)
                return@forEachIndexed
            }
            if (telling.containsMatchIn(line) && !hashWords.containsMatchIn(line)) {
                literals.firstOrNull { it.none(Char::isWhitespace) && looksRandom(it) }?.let { accept(entropyKind(line), it) }
            }
        }
    }
}
