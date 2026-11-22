package ru.codeguard.ai.context

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.nio.file.Files
import java.nio.file.Path

/**
 * Справочник уязвимостей (vulnerability-database/vulnerabilities.json) — для двух проверок AI-слоя:
 *  - идентификаторы CVE/GHSA, которые модель упоминает, должны существовать во входе или справочнике у тех же координат;
 *  - рекомендованная версия SCA должна быть вне всех уязвимых диапазонов (оценка полезности рекомендаций).
 * Сравнение версий — по правилам справочника: числовые компоненты слева направо, 1.9 == 1.9.0, квалификатор — вне области.
 */
class Advisories(private val entries: List<Entry>) {
    data class Range(val lower: String?, val lowerInclusive: Boolean, val upper: String?, val upperInclusive: Boolean)
    data class Entry(val id: String, val aliases: List<String>, val group: String, val artifact: String, val ranges: List<Range>, val fixedVersions: List<String>)

    /** Все идентификаторы (id + aliases) записей по этим координатам. */
    fun idsFor(group: String, artifact: String): Set<String> =
        entries.filter { it.group == group && it.artifact == artifact }.flatMap { listOf(it.id) + it.aliases }.toSet()

    /** Идентификаторы записи, к которой относится advisoryId (CVE ↔ GHSA одной уязвимости). */
    fun aliasesOf(advisoryId: String): Set<String> =
        entries.filter { advisoryId == it.id || advisoryId in it.aliases }.flatMap { listOf(it.id) + it.aliases }.toSet()

    /** Исправленные версии записи по id или алиасу — если анализатор не передал их в находке. */
    fun fixedVersionsOf(advisoryId: String): List<String> =
        entries.filter { advisoryId == it.id || advisoryId in it.aliases }.flatMap { it.fixedVersions }.distinct()

    /**
     * Версия попадает хотя бы в один уязвимый диапазон этих координат.
     * null — неизвестно: версию нельзя сравнить (квалификатор) или по координатам в справочнике нет записей.
     */
    fun isVulnerable(group: String, artifact: String, version: String): Boolean? {
        val v = parse(version) ?: return null
        val relevant = entries.filter { it.group == group && it.artifact == artifact }
        if (relevant.isEmpty()) return null
        return relevant.any { e -> e.ranges.any { inRange(v, it) } }
    }

    /**
     * Детерминированная целевая версия: наименьшая из исправленных версий (fixedVersions находки и всех записей справочника
     * по этим координатам), которая новее текущей и не попадает ни в один уязвимый диапазон. Понижение версии не предлагается.
     * Если безопасной нет в справочнике — наименьшая более новая из fixedVersions находки (проверка targetSafe покажет false).
     * LLM этот номер только объясняет.
     */
    fun recommend(group: String?, artifact: String?, current: String?, fixedVersions: List<String>): String? {
        val pool = (fixedVersions + if (group != null && artifact != null) entries.filter { it.group == group && it.artifact == artifact }.flatMap { it.fixedVersions } else emptyList())
            .distinct().mapNotNull { f -> parse(f)?.let { f to it } }
        val cur = current?.let { parse(it) }
        val newer = if (cur == null) pool else pool.filter { compare(it.second, cur) > 0 }
        val sorted = newer.sortedWith { x, y -> compare(x.second, y.second) }
        val safe = sorted.firstOrNull { (v, _) -> group != null && artifact != null && isVulnerable(group, artifact, v) == false }
        if (safe != null) return safe.first
        return sorted.firstOrNull { it.first in fixedVersions }?.first ?: if (cur == null) fixedVersions.firstOrNull() else null
    }

    /** Рекомендованная версия безопасна: новее текущей и вне всех диапазонов. null-неизвестность — не «безопасно». */
    fun targetSafe(group: String?, artifact: String?, current: String?, recommended: String?): Boolean {
        if (group == null || artifact == null || recommended == null) return false
        val newer = parse(recommended)?.let { r -> current?.let { parse(it) }?.let { compare(r, it) > 0 } } ?: false
        return newer && isVulnerable(group, artifact, recommended) == false
    }

    private fun inRange(v: List<Long>, r: Range): Boolean {
        r.lower?.let { lo -> val c = compare(v, parse(lo) ?: return false); if (c < 0 || (c == 0 && !r.lowerInclusive)) return false }
        r.upper?.let { up -> val c = compare(v, parse(up) ?: return false); if (c > 0 || (c == 0 && !r.upperInclusive)) return false }
        return true
    }

    companion object {
        val EMPTY = Advisories(emptyList())

        /** Числовые компоненты версии; с квалификатором (1.0-beta, 2.0.RELEASE) — null, вне области сравнения. */
        fun parse(version: String): List<Long>? {
            if (!Regex("""\d+(\.\d+)*""").matches(version.trim())) return null
            return version.trim().split('.').map { it.toLong() }
        }

        fun compare(a: List<Long>, b: List<Long>): Int {
            for (i in 0 until maxOf(a.size, b.size)) {
                val c = (a.getOrElse(i) { 0 }).compareTo(b.getOrElse(i) { 0 })
                if (c != 0) return c
            }
            return 0
        }

        fun load(path: Path): Advisories {
            if (!Files.exists(path)) return EMPTY
            return Files.newInputStream(path).use { load(it) }
        }

        fun load(input: java.io.InputStream): Advisories {
            val root = jacksonObjectMapper().readTree(input)
            val list = root.path("vulnerabilities").takeIf { it.isArray } ?: root
            return Advisories(list.map { n ->
                Entry(
                    id = n.path("id").asText(),
                    aliases = n.path("aliases").map { it.asText() },
                    group = n.path("group").asText(),
                    artifact = n.path("artifact").asText(),
                    ranges = n.path("ranges").map { r ->
                        Range(
                            r.path("lower").takeUnless { it.isNull || it.isMissingNode }?.asText(),
                            r.path("lowerInclusive").asBoolean(true),
                            r.path("upper").takeUnless { it.isNull || it.isMissingNode }?.asText(),
                            r.path("upperInclusive").asBoolean(false),
                        )
                    },
                    fixedVersions = n.path("fixedVersions").map { it.asText() },
                )
            })
        }
    }
}
