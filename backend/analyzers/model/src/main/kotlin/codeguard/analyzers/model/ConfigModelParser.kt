package codeguard.analyzers.model

import org.tomlj.TomlParseResult
import org.tomlj.TomlTable
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.error.MarkedYAMLException
import org.yaml.snakeyaml.error.YAMLException
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import org.yaml.snakeyaml.nodes.Tag
import java.io.StringReader
import java.util.Collections
import java.util.IdentityHashMap
import java.util.Properties

enum class ConfigKind { LITERAL, ENV, ENV_WITH_DEFAULT, EMPTY }

data class ConfigEntry(val key: String, val value: String, val kind: ConfigKind, val location: Location) {
    val path: String get() = location.path
    val line: Int get() = location.line

    override fun toString(): String = "ConfigEntry(kind=$kind, location=$location)"
}

internal fun parseConfig(
    files: List<SourceFile>,
    catalogs: Map<String, TomlParseResult>,
    errors: MutableList<ParseError>,
): List<ConfigEntry> = buildList {
    for (file in files) {
        when (file.type) {
            SourceType.YAML -> readYamlDocuments(file, errors) { addYamlEntries(file, it, this, errors) }
            SourceType.PROPERTIES -> addPropertiesEntries(file, this, errors)
            SourceType.ENV -> addEnvEntries(file, this, errors)
            SourceType.DOCKERFILE -> addDockerfileEntries(file, this)
            SourceType.JSON -> addJsonEntries(file, this)
            SourceType.XML -> addAll(readXmlConfig(file, errors))
            SourceType.TOML -> catalogs[file.path]?.let { addCatalogEntries(file, it, this) }
            else -> Unit
        }
    }
}

private fun addCatalogEntries(file: SourceFile, catalog: TomlTable, entries: MutableList<ConfigEntry>) {
    val versions = catalog.get("versions") as? TomlTable ?: return
    for (key in versions.keySet()) {
        val alias = listOf(key)
        val version = versions.get(alias) as? String ?: continue
        val line = versions.inputPositionOf(alias)?.line() ?: continue
        entries.add(ConfigEntry(key, version, configKind(version), Location(file.path, line)))
    }
}

/** Compose syntax nodes only. Constructing objects from YAML tags is unnecessary. */
internal fun readYamlDocuments(file: SourceFile, errors: MutableList<ParseError>, consume: (Node) -> Unit) {
    val options = LoaderOptions().apply {
        maxAliasesForCollections = 50
        nestingDepthLimit = 50
    }
    try {
        for (document in Yaml(options).composeAll(StringReader(file.text))) consume(document)
    } catch (error: MarkedYAMLException) {
        errors.add(ParseError(file.path, error.problemMark?.line?.plus(1), "Invalid or unsupported YAML"))
    } catch (_: YAMLException) {
        errors.add(ParseError(file.path, null, "Invalid or unsupported YAML"))
    }
}

private fun addYamlEntries(
    file: SourceFile,
    document: Node,
    entries: MutableList<ConfigEntry>,
    errors: MutableList<ParseError>,
) {
    val ancestors = Collections.newSetFromMap(IdentityHashMap<Node, Boolean>())
    var remaining = 100_000
    var remainingKeyCharacters = 8_000_000
    fun expansionLimit(origin: Node): Boolean {
        errors.add(ParseError(file.path, origin.startMark.line + 1, "YAML configuration expansion limit reached"))
        return false
    }

    fun visit(node: Node, prefix: String, origin: Node): Boolean {
        remainingKeyCharacters -= prefix.length
        if (remaining-- == 0 || remainingKeyCharacters < 0) return expansionLimit(origin)
        if (!ancestors.add(node)) {
            errors.add(ParseError(file.path, origin.startMark.line + 1, "Recursive YAML configuration alias"))
            return true
        }
        try {
            when (node) {
                is ScalarNode -> if (prefix.isNotEmpty()) {
                    val value = if (node.tag == Tag.NULL) "" else node.value
                    val start = origin.startMark.line + 1
                    val end = node.endMark.line + if (node.endMark.column == 0) 0 else 1
                    entries.add(ConfigEntry(prefix, value, configKind(value), Location(file.path, start, end.takeIf { it > start })))
                }
                is MappingNode -> for (pair in node.value) {
                    val key = pair.keyNode
                    if (key !is ScalarNode) {
                        errors.add(ParseError(file.path, key.startMark.line + 1, "Unsupported YAML configuration key"))
                        continue
                    }
                    val path = when {
                        key.tag == Tag.MERGE || key.value.isEmpty() -> prefix
                        prefix.isEmpty() -> key.value
                        else -> "$prefix.${key.value}"
                    }
                    if (!visit(pair.valueNode, path, key)) return false
                }
                is SequenceNode -> for ((index, value) in node.value.withIndex()) {
                    val path = if (origin is ScalarNode && origin.tag == Tag.MERGE) prefix else "$prefix[$index]"
                    if (!visit(value, path, value)) return false
                }
            }
            return true
        } finally {
            ancestors.remove(node)
        }
    }

    visit(document, "", document)
}

private fun addPropertiesEntries(file: SourceFile, entries: MutableList<ConfigEntry>, errors: MutableList<ParseError>) {
    val lines = file.text.removePrefix("\uFEFF").lineSequence().iterator()
    var line = 0
    while (lines.hasNext()) {
        val first = lines.next()
        val start = ++line
        val trimmed = first.trimStart(' ', '\t', '\u000c')
        if (trimmed.isEmpty() || trimmed.startsWith('#') || trimmed.startsWith('!')) continue
        val logicalLine = StringBuilder(first)
        var last = first
        while (last.takeLastWhile { it == '\\' }.length % 2 == 1 && lines.hasNext()) {
            last = lines.next()
            line++
            logicalLine.append('\n').append(last)
        }
        val properties = Properties()
        try {
            properties.load(StringReader(logicalLine.toString()))
            for ((key, value) in properties) {
                val literal = value as String
                val location = Location(file.path, start, line.takeIf { it > start })
                entries.add(ConfigEntry(key as String, literal, configKind(literal), location))
            }
        } catch (_: IllegalArgumentException) {
            errors.add(ParseError(file.path, start, "Invalid properties escape"))
        }
    }
}

private val envAssignment = Regex("""(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*(.*)""")

private fun addEnvEntries(file: SourceFile, entries: MutableList<ConfigEntry>, errors: MutableList<ParseError>) {
    val lines = file.text.removePrefix("\uFEFF").lineSequence().iterator()
    var line = 0
    while (lines.hasNext()) {
        val statement = lines.next().trimStart()
        val start = ++line
        if (statement.isEmpty() || statement.startsWith('#')) continue
        val assignment = envAssignment.matchEntire(statement)
        if (assignment == null) {
            errors.add(ParseError(file.path, start, "Invalid environment assignment"))
            continue
        }
        val (key, raw) = assignment.destructured
        val quote = raw.firstOrNull()?.takeIf { it == '\'' || it == '"' }
        val value: String
        if (quote == null) {
            val comment = raw.indices.firstOrNull { raw[it] == '#' && (it == 0 || raw[it - 1].isWhitespace()) }
            value = raw.substring(0, comment ?: raw.length).trimEnd()
        } else {
            val quoted = StringBuilder(raw.substring(1))
            var end = closingQuote(quoted, quote, 0)
            while (end == -1 && lines.hasNext()) {
                line++
                val previousLength = quoted.length
                quoted.append('\n').append(lines.next())
                end = closingQuote(quoted, quote, previousLength)
            }
            if (end == -1 || !quoted.substring(end + 1).trim().let { it.isEmpty() || it.startsWith('#') }) {
                errors.add(ParseError(file.path, start, "Invalid quoted environment value"))
                continue
            }
            value = quoted.substring(0, end)
        }
        val kind = if (quote == '\'' && value.isNotEmpty()) ConfigKind.LITERAL else configKind(value, dotenv = true)
        val decoded = when (quote) {
            '"' -> Regex("""\\([nrt"\\$])""").replace(value) {
                when (it.groupValues[1]) {
                    "n" -> "\n"
                    "r" -> "\r"
                    "t" -> "\t"
                    else -> it.groupValues[1]
                }
            }
            '\'' -> value.replace("\\'", "'")
            else -> value
        }
        entries.add(ConfigEntry(key, decoded, kind, Location(file.path, start, line.takeIf { it > start })))
    }
}

private fun closingQuote(value: CharSequence, quote: Char, from: Int): Int {
    var escaped = false
    for (index in from until value.length) {
        val character = value[index]
        if (character == quote && !escaped) return index
        escaped = character == '\\' && !escaped
    }
    return -1
}

private val envName = Regex("""[A-Za-z_][A-Za-z0-9_.-]*""")
private val bareEnvName = Regex("""\$[A-Za-z_][A-Za-z0-9_]*""")

internal fun configKind(value: String, dotenv: Boolean = false): ConfigKind {
    if (value.isEmpty()) return ConfigKind.EMPTY
    if (dotenv && bareEnvName.matches(value)) return ConfigKind.ENV
    if (!value.startsWith("\${") || !value.endsWith('}')) return ConfigKind.LITERAL

    var level = 1
    var separator: Int? = null
    for (index in 2 until value.length) {
        val character = value[index]
        if (character == '{' && value[index - 1] == '$') level++
        if (character == ':' && level == 1 && separator == null) separator = index
        if (character == '}' && --level == 0) {
            if (index != value.lastIndex) return ConfigKind.LITERAL
            val nameEnd = separator ?: index
            val name = if (dotenv && separator == null) value.substring(2, nameEnd).substringBefore('-') else value.substring(2, nameEnd)
            if (!envName.matches(name)) return ConfigKind.LITERAL
            return if (separator != null || name.length != nameEnd - 2) ConfigKind.ENV_WITH_DEFAULT else ConfigKind.ENV
        }
    }
    return ConfigKind.LITERAL
}
