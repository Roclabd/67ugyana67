package workflow.app

import com.fasterxml.jackson.databind.JsonNode

/** Результат построения готового патча для находки. */
sealed interface PatchOutcome {
    /** [diff] применяется `git apply`; [preview] - то же без секрета (для показа на экране). */
    data class Ready(val diff: String, val preview: String) : PatchOutcome

    /** Находка поддерживается, но место правки ненадёжно (HTTP 409). */
    data class Unsupported(val message: String) : PatchOutcome

    /** Для класса находки автоисправления нет (HTTP 404). */
    data class NoAutofix(val message: String) : PatchOutcome
}

const val NO_AUTOFIX_MESSAGE = "Автоисправление для этого класса не поддерживается, см. рекомендацию"

/**
 * Детерминированные патчи по снимку проекта: SCA (повышение версии до первой безопасной по справочнику)
 * и SECRET (замена литерала ссылкой на переменную окружения). Пути в diff относительны корню проверенного проекта.
 */
object FindingPatches {
    /** [read] возвращает текст файла снимка по относительному пути или null. */
    fun create(finding: JsonNode, read: (String) -> String?): PatchOutcome = try {
        when (finding.path("category").asText()) {
            "SCA" -> scaPatch(finding, read)
            "SECRET" -> secretPatch(finding, read)
            else -> PatchOutcome.NoAutofix(NO_AUTOFIX_MESSAGE)
        }
    } catch (_: IllegalArgumentException) {
        PatchOutcome.Unsupported("Не удалось надёжно построить патч для этой находки.")
    }

    // ───────────── SCA ─────────────

    private val upgradeText = Regex("до версии ([0-9]+(?:\\.[0-9]+)*)\\.?")

    private fun scaPatch(finding: JsonNode, read: (String) -> String?): PatchOutcome {
        val current = finding.path("version").asText()
        val target = upgradeText.find(finding.path("remediation").asText())?.groupValues?.get(1)
            ?: return PatchOutcome.Unsupported(
                "В справочнике нет безопасной версии, которая выходит за все уязвимые диапазоны: исправьте зависимость вручную.")
        if (current.isEmpty()) return PatchOutcome.Unsupported("В находке не указана текущая версия.")
        val evidence = finding.path("evidence").toList().ifEmpty {
            listOf(finding)
        }
        if (evidence.any { it.hasNonNull("note") }) {
            return PatchOutcome.Unsupported("Версия задаётся через Spring Boot BOM: смените релиз BOM вручную.")
        }
        val literal = Regex("(?<![0-9A-Za-z.])" + Regex.escape(current) + "(?![0-9]|\\.[0-9])")
        // gradle.lockfile генерируется Gradle: правим источник версии, а файл блокировок пересоберёт `--write-locks`.
        val places = evidence.filterNot { it.path("path").asText().endsWith(".lockfile") }.mapNotNull { item ->
            val path = item.path("path").asText().takeIf(String::isNotEmpty) ?: return@mapNotNull null
            val line = item.path("line").asInt(0).takeIf { it > 0 } ?: return@mapNotNull null
            val text = read(path) ?: return@mapNotNull null
            val source = text.split("\n").getOrNull(line - 1)?.removeSuffix("\r") ?: return@mapNotNull null
            val found = literal.findAll(source).toList()
            if (found.isEmpty()) null else Triple(path, line, source) to found
        }.distinctBy { it.first.first to it.first.second }
        if (places.isEmpty()) return PatchOutcome.Unsupported(
            "Версия $current не записана литералом ни в одном из мест объявления (вычисляется или приходит из каталога): обновите её вручную.")
        if (places.size > 1) return PatchOutcome.Unsupported(
            "Версия $current встречается в нескольких местах (${places.joinToString { it.first.first + ":" + it.first.second }}): выберите место вручную.")
        val (place, matches) = places.single()
        if (matches.size != 1) return PatchOutcome.Unsupported(
            "В строке ${place.first}:${place.second} версия $current встречается несколько раз: исправьте вручную.")
        val (path, line, source) = place
        val range = matches.single().range
        val changed = source.replaceRange(range, target)
        val text = read(path) ?: return PatchOutcome.Unsupported("Файл $path недоступен.")
        val diff = lineDiff(path, text, line, changed)
        return PatchOutcome.Ready(diff, diff)
    }

    // ───────────── SECRET ─────────────

    private fun secretPatch(finding: JsonNode, read: (String) -> String?): PatchOutcome {
        val path = finding.path("path").asText()
        val line = finding.path("line").asInt(0)
        if (finding.path("endLine").asInt(line) > line) {
            return PatchOutcome.Unsupported("Секрет занимает несколько строк: замените значение вручную.")
        }
        val text = read(path) ?: return PatchOutcome.Unsupported("Файл $path недоступен в снимке.")
        val source = text.split("\n").getOrNull(line - 1)?.removeSuffix("\r")
            ?: return PatchOutcome.Unsupported("Строка $line отсутствует в файле $path.")
        val lowerPath = path.lowercase()
        val replaced = when {
            lowerPath.endsWith(".kt") || lowerPath.endsWith(".kts") -> codeReplacement(source, kotlin = true)
            lowerPath.endsWith(".java") -> codeReplacement(source, kotlin = false)
            lowerPath.endsWith(".properties") -> propertiesReplacement(source)
            lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml") -> yamlReplacement(text, line)
            else -> null
        } ?: return PatchOutcome.Unsupported(
            "Не удалось безопасно определить значение и имя переменной в этой строке: вынесите секрет в окружение вручную.")
        return PatchOutcome.Ready(lineDiff(path, text, line, replaced.new), lineDiff(path, text, line, replaced.new, replaced.maskedOld))
    }

    private class Replacement(val new: String, val maskedOld: String)

    /** Присваивание `name = "литерал"` или пара `"name" to "литерал"`. */
    private val assignment = Regex("([A-Za-z_][A-Za-z0-9_]*)\\s*(?::\\s*[A-Za-z0-9_.<>?]+\\s*)?=\\s*\"")
    private val keyedPair = Regex("\"([A-Za-z_][A-Za-z0-9_.-]*)\"\\s*(?:to|,|:)\\s*\"")

    private fun codeReplacement(source: String, kotlin: Boolean): Replacement? {
        val starts = (assignment.findAll(source).map { it.groupValues[1] to it.range.last } +
            keyedPair.findAll(source).map { it.groupValues[1] to it.range.last }).toList()
        if (starts.size != 1) return null
        val (name, quote) = starts.single()
        val end = closingQuote(source, quote + 1) ?: return null
        val value = source.substring(quote + 1, end)
        if (value.isEmpty() || value.contains('$') || value.contains("\\")) return null
        val variable = envName(name).takeIf { it.isNotEmpty() } ?: return null
        val call = if (kotlin) "System.getenv(\"$variable\") ?: error(\"$variable is not set\")" else "System.getenv(\"$variable\")"
        val after = source.substring(end + 1).trimStart()
        val bare = after.isEmpty() || after[0] in ",;)}"
        val expression = if (bare || !kotlin) call else "($call)"
        val head = source.substring(0, quote).let { if (kotlin) it.replace(Regex("\\bconst\\s+val\\b"), "val") else it }
        return Replacement(head + expression + source.substring(end + 1), source.substring(0, quote + 1) + "****" + source.substring(end))
    }

    private fun closingQuote(source: String, from: Int): Int? {
        var index = from
        while (index < source.length) {
            when (source[index]) {
                '\\' -> index++
                '"' -> return index
            }
            index++
        }
        return null
    }

    private val propertiesLine = Regex("^(\\s*)([A-Za-z0-9_.\\-\\[\\]]+)(\\s*[=:]\\s*)(\\S.*?)\\s*$")

    private fun propertiesReplacement(source: String): Replacement? {
        if (source.trimStart().startsWith("#") || source.trimStart().startsWith("!")) return null
        val match = propertiesLine.matchEntire(source) ?: return null
        val value = match.groupValues[4]
        if (value.contains("\${")) return null
        val head = source.substring(0, match.groups[4]!!.range.first)
        val variable = envName(match.groupValues[2]).takeIf { it.isNotEmpty() } ?: return null
        return Replacement("$head\${$variable}", "$head****")
    }

    private val yamlLine = Regex("^(\\s*)(?:-\\s+)?([A-Za-z0-9_.\\-]+)(\\s*:\\s+)(\\S.*?)\\s*$")

    private fun yamlReplacement(text: String, line: Int): Replacement? {
        val lines = text.split("\n").map { it.removeSuffix("\r") }
        val source = lines[line - 1]
        val match = yamlLine.matchEntire(source) ?: return null
        var value = match.groupValues[4]
        if (value.contains("\${") || value.startsWith("|") || value.startsWith(">") || value.startsWith("&") ||
            value.startsWith("*") || value.contains(" #")) return null
        val quote = value.firstOrNull()?.takeIf { it == '"' || it == '\'' }
        if (quote != null) {
            if (value.length < 2 || value.last() != quote) return null
            value = value.substring(1, value.length - 1)
        }
        if (value.isEmpty()) return null
        val indent = match.groupValues[1].length
        val parents = mutableListOf<String>()
        var level = indent
        for (index in line - 2 downTo 0) {
            val parent = lines[index]
            if (parent.isBlank() || parent.trimStart().startsWith("#")) continue
            val spaces = parent.length - parent.trimStart().length
            if (spaces >= level) continue
            val key = Regex("^\\s*(?:-\\s+)?([A-Za-z0-9_.\\-]+)\\s*:\\s*$").matchEntire(parent)?.groupValues?.get(1) ?: break
            parents.add(0, key)
            level = spaces
            if (level == 0) break
        }
        val variable = envName((parents + match.groupValues[2]).joinToString("_")).takeIf { it.isNotEmpty() } ?: return null
        val head = source.substring(0, match.groups[4]!!.range.first)
        val wrap = quote?.toString().orEmpty()
        return Replacement("$head$wrap\${$variable}$wrap", "$head$wrap****$wrap")
    }

    /** `apiKey` → `API_KEY`, `spring.datasource.password` → `SPRING_DATASOURCE_PASSWORD`. */
    fun envName(identifier: String): String = identifier
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("[^A-Za-z0-9]+"), "_")
        .trim('_').uppercase()
        .let { if (it.firstOrNull()?.isDigit() == true) "_$it" else it }

    // ───────────── unified diff ─────────────

    /**
     * Unified diff с заменой одной строки [line] (с 1) на [replacement]. [displayedOld] подменяет удаляемую строку
     * в показе (для маскирования). Окончания строк и отсутствие перевода строки в конце файла сохраняются.
     */
    fun lineDiff(path: String, text: String, line: Int, replacement: String, displayedOld: String? = null): String {
        val endsWithNewline = text.endsWith("\n")
        val lines = text.split("\n").let { if (endsWithNewline) it.dropLast(1) else it }
        require(line in 1..lines.size)
        val crlf = lines[line - 1].endsWith("\r")
        val first = maxOf(1, line - 3)
        val last = minOf(lines.size, line + 3)
        val marker = "\\ No newline at end of file"
        val out = StringBuilder()
        out.append("--- a/").append(path).append('\n').append("+++ b/").append(path).append('\n')
        out.append("@@ -$first,${last - first + 1} +$first,${last - first + 1} @@\n")
        for (number in first..last) {
            val original = lines[number - 1]
            val noEol = number == lines.size && !endsWithNewline
            if (number == line) {
                val old = displayedOld?.let { it + if (crlf) "\r" else "" } ?: original
                out.append('-').append(old).append('\n')
                if (noEol) out.append(marker).append('\n')
                out.append('+').append(replacement).append(if (crlf) "\r" else "").append('\n')
                if (noEol) out.append(marker).append('\n')
            } else {
                out.append(' ').append(original).append('\n')
                if (noEol) out.append(marker).append('\n')
            }
        }
        return out.toString()
    }
}
