package ru.codeguard.sast.export

import ru.codeguard.sast.model.SastCoverage
import ru.codeguard.sast.model.SastResult

/** Экспорт SAST-находок в JSON авторов набора и покрытия в форме $defs/coverage. Без внешних библиотек. */
object OrganizerJson {

    fun toJson(result: SastResult): String {
        if (result.findings.isEmpty()) return "{\n  \"findings\": []\n}\n"
        val sb = StringBuilder()
        sb.append("{\n  \"findings\": [\n")
        result.findings.forEachIndexed { i, f ->
            val fields = mutableListOf<String>()
            fields += "      \"category\": ${str("SAST")}"
            fields += "      \"path\": ${str(f.path)}"
            fields += "      \"class\": ${str(f.sastClass)}"
            fields += "      \"line\": ${f.line}"
            val end = f.endLine
            if (end != null && end > f.line) fields += "      \"endLine\": $end"
            fields += "      \"severity\": ${str(f.severity.name)}"
            fields += "      \"description\": ${str(f.description)}"
            fields += "      \"remediation\": ${str(f.remediation)}"
            sb.append("    {\n").append(fields.joinToString(",\n")).append("\n    }")
            if (i < result.findings.size - 1) sb.append(',')
            sb.append('\n')
        }
        sb.append("  ]\n}\n")
        return sb.toString()
    }

    fun coverageJson(result: SastResult): String = coverageJson(result.coverage)

    fun coverageJson(c: SastCoverage): String {
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"status\": ${str(c.status.name)},\n")
        sb.append("  \"filesAnalyzed\": ${c.filesAnalyzed},\n")
        sb.append("  \"filesSkipped\": ").append(array(c.filesSkipped.map { s ->
            obj(listOfNotNull("path" to str(s.path), "reason" to str(s.reason), s.line?.let { "line" to it.toString() }))
        })).append(",\n")
        sb.append("  \"rulesApplied\": ").append(array(c.rulesApplied.map { str(it) })).append(",\n")
        sb.append("  \"unresolved\": ").append(array(c.unresolved.map { u ->
            obj(listOfNotNull(
                "kind" to str(u.kind), "path" to str(u.path),
                u.line?.let { "line" to it.toString() },
                "reason" to str(u.reason),
                u.subject?.let { "subject" to str(it) },
            ))
        })).append(",\n")
        sb.append("  \"dismissed\": ").append(array(c.dismissed.map { d ->
            obj(listOfNotNull("rule" to str(d.rule), "path" to str(d.path), d.line?.let { "line" to it.toString() }, "reason" to str(d.reason)))
        })).append("\n}\n")
        return sb.toString()
    }

    private fun array(items: List<String>): String =
        if (items.isEmpty()) "[]" else items.joinToString(",\n", "[\n", "\n  ]") { "    $it" }

    private fun obj(fields: List<Pair<String, String>>): String =
        fields.joinToString(", ", "{", "}") { (k, v) -> "${str(k)}: $v" }

    /** JSON-строка с экранированием кавычек, обратного слеша и управляющих символов. */
    fun str(s: String): String {
        val sb = StringBuilder(s.length + 2).append('"')
        for (ch in s) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (ch < ' ' || ch == '\u007F') sb.append("\\u%04x".format(ch.code)) else sb.append(ch)
            }
        }
        return sb.append('"').toString()
    }
}
