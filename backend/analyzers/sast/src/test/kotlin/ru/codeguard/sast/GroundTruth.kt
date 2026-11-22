package ru.codeguard.sast

import ru.codeguard.sast.model.SastFinding
import java.nio.file.Files
import java.nio.file.Path

/** Запись эталона: класс, путь, включительный диапазон строк. */
data class GtEntry(val cls: String, val path: String, val line: Int, val endLine: Int?, val reason: String? = null) {
    val last: Int get() = endLine ?: line
    override fun toString() = "$cls $path:$line" + (endLine?.let { "-$it" } ?: "")
}

data class MatchResult(
    val tp: Int,
    val fp: List<SastFinding>,
    val fn: List<GtEntry>,
    val controlHits: List<Pair<SastFinding, GtEntry>>,
)

object GroundTruth {

    /** expected.json вариантов: {"findings":[...], "controls":[...]}. */
    fun readExpected(file: Path): Pair<List<GtEntry>, List<GtEntry>> {
        val root = MiniJson.parse(Files.readString(file)) as Map<*, *>
        return entries(root["findings"], null) to entries(root["controls"], null)
    }

    /** SAST-часть эталона авторов набора: findings и controls с category=SAST. */
    fun readOrganizerSast(file: Path): Pair<List<GtEntry>, List<GtEntry>> {
        val root = MiniJson.parse(Files.readString(file)) as Map<*, *>
        return entries(root["findings"], "SAST") to entries(root["controls"], "SAST")
    }

    private fun entries(node: Any?, category: String?): List<GtEntry> =
        (node as? List<*> ?: emptyList<Any?>()).mapNotNull { it as? Map<*, *> }
            .filter { category == null || it["category"] == category }
            .map {
                GtEntry(
                    cls = it["class"] as String,
                    path = (it["path"] as String).replace('\\', '/'),
                    line = (it["line"] as Number).toInt(),
                    endLine = (it["endLine"] as? Number)?.toInt(),
                    reason = it["reason"] as? String,
                )
            }

    private fun overlaps(f: SastFinding, e: GtEntry): Boolean =
        f.sastClass == e.cls && f.path == e.path &&
            f.line <= e.last && e.line <= (f.endLine ?: f.line)

    /** Сверка по правилам авторов набора: каждая находка закрывает максимум одну запись эталона (жадно). */
    fun match(findings: List<SastFinding>, expected: List<GtEntry>, controls: List<GtEntry>): MatchResult {
        val free = expected.toMutableList()
        val fp = mutableListOf<SastFinding>()
        var tp = 0
        for (f in findings) {
            val hit = free.firstOrNull { overlaps(f, it) }
            if (hit != null) { free.remove(hit); tp++ } else fp += f
        }
        val hits = findings.flatMap { f -> controls.filter { overlaps(f, it) }.map { f to it } }
        return MatchResult(tp, fp, free, hits)
    }

    private fun fmt(f: SastFinding) = "${f.sastClass} ${f.path}:${f.line}-${f.endLine ?: f.line} [${f.rule}]"

    /** Подробное описание расхождений для сообщения об ошибке. */
    fun describe(r: MatchResult, findings: List<SastFinding>): String = buildString {
        appendLine("tp=${r.tp}")
        appendLine("fn (пропущено): ${r.fn.joinToString()}")
        appendLine("fp (лишнее): ${r.fp.joinToString { fmt(it) }}")
        appendLine("controlHits: ${r.controlHits.joinToString { (f, c) -> "${fmt(f)} ~ контроль $c" }}")
        appendLine("Находки анализатора:")
        findings.forEach { appendLine("  ${fmt(it)}") }
    }
}

/** Минимальный JSON-парсер: Map, List, String, Long/Double, Boolean, null. */
object MiniJson {
    fun parse(text: String): Any? {
        val src = text.removePrefix("﻿")
        val p = Parser(src)
        val v = p.value()
        p.ws()
        require(p.i == src.length) { "Лишние данные после JSON на позиции ${p.i}" }
        return v
    }

    private class Parser(val s: String) {
        var i = 0

        fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }

        fun value(): Any? {
            ws()
            require(i < s.length) { "Неожиданный конец JSON" }
            val c = s[i]
            return when {
                c == '{' -> obj()
                c == '[' -> arr()
                c == '"' -> str()
                c == 't' -> lit("true", true)
                c == 'f' -> lit("false", false)
                c == 'n' -> lit("null", null)
                c == '-' || c.isDigit() -> num()
                else -> error("Неожиданный символ '$c' на позиции $i")
            }
        }

        fun lit(word: String, v: Any?): Any? {
            require(s.startsWith(word, i)) { "Ожидалось $word на позиции $i" }
            i += word.length
            return v
        }

        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++; ws()
            if (s[i] == '}') { i++; return m }
            while (true) {
                ws()
                val k = str()
                ws()
                require(s[i] == ':') { "Ожидалось ':' на позиции $i" }
                i++
                m[k] = value()
                ws()
                val c = s[i++]
                if (c == '}') return m
                require(c == ',') { "Ожидалось ',' или '}' на позиции ${i - 1}" }
            }
        }

        fun arr(): List<Any?> {
            val l = ArrayList<Any?>()
            i++; ws()
            if (s[i] == ']') { i++; return l }
            while (true) {
                l += value()
                ws()
                val c = s[i++]
                if (c == ']') return l
                require(c == ',') { "Ожидалось ',' или ']' на позиции ${i - 1}" }
            }
        }

        fun str(): String {
            require(s[i] == '"') { "Ожидалась строка на позиции $i" }
            i++
            val sb = StringBuilder()
            while (true) {
                val c = s[i++]
                if (c == '"') return sb.toString()
                if (c != '\\') { sb.append(c); continue }
                when (val e = s[i++]) {
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> sb.append(e) // \" \\ \/
                }
            }
        }

        fun num(): Number {
            val st = i
            if (s[i] == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            val t = s.substring(st, i)
            return t.toLongOrNull() ?: t.toDouble()
        }
    }
}
