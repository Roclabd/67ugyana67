package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceType

private val insertStatement = Regex(
    """(?is)insert\s+(?:or\s+\w+\s+)?into\s+[\w."`\[\]]+\s*\(([^)]*)\)\s*values\s*(.*?)(?:;|\z)""",
)
private val hashedValue = Regex("""^(?:\{[a-z0-9]+}.*|\$2[abxy]\$\d\d\$.{50,}|\${'$'}argon2.*|[0-9a-f]{32,})$""", RegexOption.IGNORE_CASE)

private fun splitTuple(text: String, from: Int): Pair<List<String>, Int>? {
    var i = text.indexOf('(', from)
    if (i < 0) return null
    i++
    val items = mutableListOf<String>()
    val current = StringBuilder()
    var depth = 0
    while (i < text.length) {
        val c = text[i]
        when {
            c == '\'' -> {
                current.append(c)
                i++
                while (i < text.length) {
                    current.append(text[i])
                    if (text[i] == '\'') {
                        if (text.getOrNull(i + 1) == '\'') { i++; current.append('\'') } else break
                    }
                    i++
                }
            }
            c == '(' -> { depth++; current.append(c) }
            c == ')' -> {
                if (depth == 0) { items += current.toString().trim(); return items to i + 1 }
                depth--; current.append(c)
            }
            c == ',' && depth == 0 -> { items += current.toString().trim(); current.clear() }
            else -> current.append(c)
        }
        i++
    }
    return null
}

/** `INSERT INTO users(login, password) VALUES ('admin', 'pw')`: только явные столбцы password/secret с литералом. */
internal fun scanSqlSecrets(model: ProjectModel): List<SecretCandidate> = buildList {
    for (file in model.files.filter { it.type == SourceType.SQL }) {
        for (insert in insertStatement.findAll(file.text)) {
            val columns = insert.groupValues[1].split(',').map { it.trim().trim('"', '`', '[', ']') }
            val targets = columns.withIndex().filter { (_, name) ->
                secretKind(name) != null && (name.lowercase().contains("password") || name.lowercase().contains("secret") ||
                    name.lowercase() in setOf("passwd", "pwd", "pass"))
            }
            if (targets.isEmpty()) continue
            val valuesStart = insert.groups[2]!!.range.first
            var cursor = 0
            val body = insert.groupValues[2]
            while (true) {
                val (tuple, next) = splitTuple(body, cursor) ?: break
                cursor = next
                for ((index, name) in targets) {
                    val raw = tuple.getOrNull(index) ?: continue
                    if (!raw.startsWith('\'') || !raw.endsWith('\'') || raw.length < 3) continue
                    val value = raw.substring(1, raw.length - 1).replace("''", "'")
                    if (isPlaceholder(value) || hashedValue.matches(value) || value.contains("\${") || value.startsWith(":") || value == "?") continue
                    val offset = valuesStart + body.indexOf(raw, (cursor - raw.length - 2).coerceAtLeast(0)).coerceAtLeast(0)
                    val line = file.lineAt(offset.coerceIn(0, file.text.length))
                    add(SecretCandidate(secretKind(name) ?: "password", value, Location(file.path, line)))
                }
            }
        }
    }
}
