package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceFile
import codeguard.analyzers.model.SourceType

/*
 * Скрипты и конфигурации вне разбираемых форматов (.sh, .conf, .ini, .txt, .http): читаем как текст и ищем
 * присваивания `NAME=value`, заголовки `X-Api-Key: …`, `Authorization: Bearer …`, URL с паролем и известные форматы ключей.
 */

private val otherTextExtensions = setOf("sh", "bash", "conf", "ini", "cfg", "txt", "http", "rest")
private val assignment = Regex("""^\s*(?:export\s+|set\s+|declare\s+(?:-x\s+)?|@|-{1,2})?([A-Za-z_][A-Za-z0-9_.-]*)\s*([=:])\s*(.+?)\s*$""")
private val headerLine = Regex("""(?<![\w-])([A-Za-z][A-Za-z0-9-]{2,}):\s*(?:(?:Bearer|Basic|Token)\s+)?([^\s"';]+)""")
private val nginxHeader = Regex("""(?:proxy_set_header|add_header)\s+([A-Za-z][A-Za-z0-9-]+)\s+"?([^";\s]+)""")
private val shellDefaultValue = Regex("""^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)}$""")

internal fun SourceFile.isOtherTextSource(): Boolean =
    type == SourceType.OTHER && text.isNotEmpty() && path.substringAfterLast('.', "").lowercase() in otherTextExtensions

private fun unquote(value: String): String {
    val v = value.trim()
    if (v.length >= 2 && (v[0] == '"' || v[0] == '\'') && v.last() == v[0]) return v.substring(1, v.length - 1)
    // Незакавыченное значение заканчивается на пробеле перед комментарием или `;`.
    return v.substringBefore(" #").substringBefore(';').trim().trim('"', '\'')
}

internal fun scanOtherTextSecrets(model: ProjectModel): List<SecretCandidate> = buildList {
    for (file in model.files.filter { it.isOtherTextSource() }) {
        val strict = file.path.substringAfterLast('.').lowercase() == "txt"
        file.text.lineSequence().forEachIndexed { index, rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) return@forEachIndexed
            val location = Location(file.path, index + 1)
            fun accept(kind: String, value: String) {
                add(SecretCandidate(kind, value, location))
            }
            fun usable(value: String, minimum: Int): Boolean =
                value.isNotEmpty() && '$' !in value && "{{" !in value && !isPlaceholder(value) && value.length >= minimum

            embeddedCredential(line)?.let { (kind, secret) -> accept(kind, secret); return@forEachIndexed }
            knownTokenShape(line)?.let { (kind, secret) -> accept(kind, secret); return@forEachIndexed }

            for (match in listOf(headerLine.find(line), nginxHeader.find(line))) {
                val name = match?.groupValues?.get(1) ?: continue
                val kind = headerKind(name) ?: continue
                val value = match.groupValues[2]
                if (usable(value, 6)) { accept(kind, value); return@forEachIndexed }
            }

            val match = assignment.matchEntire(line) ?: return@forEachIndexed
            val name = match.groupValues[1]
            val separator = match.groupValues[2]
            var value = unquote(match.groupValues[3])
            shellDefaultValue.matchEntire(value)?.let { value = it.groupValues[1] }
            if (!usable(value, 1) || value.contains(' ')) return@forEachIndexed
            val strong = secretKind(name)
            val looksReal = looksLikeSecretValue(value, if (strong != null) 6 else 8)
            val kind = when {
                strong != null -> strong.takeIf { !strict && separator == "=" || looksReal }
                else -> weakSecretKind(name, value)
            } ?: return@forEachIndexed
            accept(kind, value)
        }
    }
}
