package codeguard.analyzers.model

private val dockerInstruction = Regex("""(?i)(ENV|ARG)[ \t]+(.+)""")
private val dockerPair = Regex("""([A-Za-z_][A-Za-z0-9_.-]*)=("[^"\\]*+(?:\\.[^"\\]*+)*+"|'[^']*'|\S*)""")
private val dockerLegacy = Regex("""([A-Za-z_][A-Za-z0-9_.-]*)[ \t]+(.+)""")

private fun unquote(raw: String): String {
    val value = raw.trim()
    return if (value.length >= 2 && (value.first() == '"' || value.first() == '\'') && value.last() == value.first()) {
        value.substring(1, value.length - 1)
    } else value
}

/** `ENV K=V K2="v 2"`, `ENV K V`, `ARG K=V`: значения, попадающие в образ. */
internal fun addDockerfileEntries(file: SourceFile, entries: MutableList<ConfigEntry>) {
    val lines = file.text.lineSequence().iterator()
    var number = 0
    while (lines.hasNext()) {
        var statement = lines.next()
        val start = ++number
        if (statement.isBlank() || statement.trimStart().startsWith('#')) continue
        while (statement.trimEnd().endsWith('\\') && lines.hasNext()) {
            statement = statement.trimEnd().removeSuffix("\\") + " " + lines.next().trim()
            number++
        }
        val instruction = dockerInstruction.matchEntire(statement.trim()) ?: continue
        val body = instruction.groupValues[2].trim()
        val location = Location(file.path, start, number.takeIf { it > start })
        fun add(key: String, raw: String) {
            val value = unquote(raw)
            entries.add(ConfigEntry(key, value, configKind(value, dotenv = true), location))
        }
        val pairs = dockerPair.findAll(body).toList()
        if (pairs.isNotEmpty() && pairs.first().range.first == 0) {
            pairs.forEach { add(it.groupValues[1], it.groupValues[2]) }
        } else if (instruction.groupValues[1].equals("ENV", true)) {
            dockerLegacy.matchEntire(body)?.let { add(it.groupValues[1], it.groupValues[2]) }
        }
    }
}

// Без чередования внутри цикла: иначе java.util.regex рекурсивно углубляется на каждый символ и падает StackOverflowError.
private val jsonPair = Regex(""""([^"\\]++(?:\\.[^"\\]*+)*+)"\s*:\s*"([^"\\]*+(?:\\.[^"\\]*+)*+)"""")

/** Пары `"ключ": "строка"` построчно: достаточно для секретов в конфигурационных JSON. */
internal fun addJsonEntries(file: SourceFile, entries: MutableList<ConfigEntry>) {
    file.text.lineSequence().forEachIndexed { index, line ->
        for (match in jsonPair.findAll(line)) {
            val value = match.groupValues[2].replace("\\\"", "\"").replace("\\\\", "\\")
            entries.add(ConfigEntry(match.groupValues[1], value, configKind(value), Location(file.path, index + 1)))
        }
    }
}
