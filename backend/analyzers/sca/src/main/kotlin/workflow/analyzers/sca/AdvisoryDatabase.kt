package workflow.analyzers.sca

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.InputStream
import java.math.BigInteger
import java.time.LocalDate
import java.time.format.DateTimeParseException

internal class AdvisoryDatabase private constructor(
    private val records: List<Record>,
    val snapshotDate: String? = null,
) {
    val size: Int get() = records.size
    val byCoordinate by lazy { records.groupBy(Record::coordinate, Record::advisory) }

    /**
     * Объединение каталогов. Проектный каталог может ДОБАВИТЬ записи и диапазоны, но не убрать и не сузить
     * встроенные: при совпадении идентификатора (или пары «координата + CVE») остаются встроенные запись,
     * серьёзность и диапазоны, а диапазоны проекта добавляются к ним.
     */
    fun overlay(project: AdvisoryDatabase): AdvisoryDatabase {
        val merged = records.toMutableList()
        for (extra in project.records) {
            val i = merged.indexOfFirst { it.sourceId == extra.sourceId || it.canonicalKey == extra.canonicalKey }
            if (i < 0) {
                merged += extra
            } else {
                val base = merged[i]
                val ranges = (base.advisory.ranges + extra.advisory.ranges).distinct()
                merged[i] = base.copy(advisory = base.advisory.copy(ranges = ranges))
            }
        }
        return AdvisoryDatabase(merged)
    }

    private data class Record(val sourceId: String, val coordinate: Coordinate, val advisory: Advisory) {
        val canonicalKey get() = coordinate to advisory.id
    }

    companion object {
        private val mapper = ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)

        fun read(source: InputStream): AdvisoryDatabase {
            val root = requireNotNull(mapper.readTree(source))
            require(root.path("formatVersion").asInt() == 1)
            require(root.path("ecosystem").asText() == "Maven")
            require(root.path("versionFormat").asText() == "numeric-dot-separated")
            val records = root.array("vulnerabilities").map { node ->
                val coordinate = Coordinate(node.string("group"), node.string("artifact"))
                val aliases = node.array("aliases").map(JsonNode::asText)
                val ranges = node.array("ranges").map { range ->
                    val lower = range.required("lower").takeUnless(JsonNode::isNull)?.asText()
                    VersionRange(
                        lower?.let { NumericVersion.requireNumeric(it) },
                        range.boolean("lowerInclusive"),
                        NumericVersion.requireNumeric(range.string("upper")),
                        range.boolean("upperInclusive"),
                    )
                }
                require(ranges.isNotEmpty())
                val fixedVersions = node.array("fixedVersions").map { NumericVersion.requireNumeric(it.asText()) }
                val sourceId = node.string("id")
                val id = aliases.firstOrNull { cveId.matches(it) } ?: sourceId
                val severity = node.string("severity")
                require(severity in severities)
                Record(sourceId, coordinate, Advisory(id, severity, ranges, fixedVersions))
            }
            val rawDate = root.path("snapshot").path("date").textValue()?.takeIf { it.length == 10 }
            val snapshotDate = try {
                rawDate?.let { LocalDate.parse(it).toString() }
            } catch (_: DateTimeParseException) {
                null
            }
            return AdvisoryDatabase(records, snapshotDate)
        }
    }
}

internal data class Coordinate(val group: String, val artifact: String) {
    override fun toString(): String = "$group:$artifact"
}

internal data class Advisory(
    val id: String,
    val severity: String,
    val ranges: List<VersionRange>,
    val fixedVersions: List<NumericVersion>,
) {
    fun affects(version: NumericVersion): Boolean = ranges.any { version in it }
}

internal class InvalidAdvisoryRange : IllegalArgumentException()

internal data class VersionRange(
    val lower: NumericVersion?,
    val lowerInclusive: Boolean,
    val upper: NumericVersion,
    val upperInclusive: Boolean,
) {
    init {
        if (lower != null) {
            val order = lower.compareTo(upper)
            if (order > 0 || order == 0 && !(lowerInclusive && upperInclusive)) throw InvalidAdvisoryRange()
        }
    }

    operator fun contains(version: NumericVersion): Boolean {
        if (lower != null) {
            val fromLower = version.compareTo(lower)
            if (fromLower < 0 || fromLower == 0 && !lowerInclusive) return false
        }
        val fromUpper = version.compareTo(upper)
        return fromUpper < 0 || fromUpper == 0 && upperInclusive
    }
}

internal class NumericVersion private constructor(
    val text: String,
    private val components: List<BigInteger>,
    private val qualifier: Qualifier? = null,
) : Comparable<NumericVersion> {
    /** Ранг квалификатора по Maven ComparableVersion: пре-релизы ниже релиза, `jre`/`android` выше. */
    private class Qualifier(val rank: Int, val word: String, val number: BigInteger)

    override fun compareTo(other: NumericVersion): Int {
        for (index in 0 until maxOf(components.size, other.components.size)) {
            val comparison = components.getOrElse(index) { BigInteger.ZERO }
                .compareTo(other.components.getOrElse(index) { BigInteger.ZERO })
            if (comparison != 0) return comparison
        }
        val left = qualifier
        val right = other.qualifier
        val leftRank = left?.rank ?: RELEASE_RANK
        val rightRank = right?.rank ?: RELEASE_RANK
        if (leftRank != rightRank) return leftRank.compareTo(rightRank)
        if (left == null || right == null) return 0
        val byWord = left.word.compareTo(right.word)
        return if (byWord != 0 && leftRank > RELEASE_RANK) byWord else left.number.compareTo(right.number)
    }

    companion object {
        private const val RELEASE_RANK = 0
        private const val UNKNOWN_RANK = 1
        private val qualifierRanks = mapOf(
            // Пре-релизы (alpha/beta/m/rc) намеренно не разбираются: контрольный корпус требует молчать на 2.8.9-RC1.
            "release" to 0, "ga" to 0, "final" to 0,
            "jre" to UNKNOWN_RANK, "android" to UNKNOWN_RANK,
        )
        private val mavenVersion = Regex("([0-9]+(?:\\.[0-9]+)*)(?:[.-]([A-Za-z]+)[.-]?([0-9]+)?)?")

        fun parse(value: String?): NumericVersion? = value?.takeIf(numericVersion::matches)
            ?.let { NumericVersion(it, it.split('.').map(String::toBigInteger)) }

        /**
         * Версия зависимости: числа плюс известный квалификатор (`31.1-jre`, `5.3.20.RELEASE`, `1.0.0-RC1`).
         * Неизвестные (`-preview`) и `-SNAPSHOT` остаются неразобранными.
         */
        fun parseDependency(value: String?): NumericVersion? {
            parse(value)?.let { return it }
            val match = value?.let(mavenVersion::matchEntire) ?: return null
            val word = match.groupValues[2].lowercase()
            val rank = qualifierRanks[word] ?: return null
            val number = match.groupValues[3].ifEmpty { "0" }.toBigInteger()
            val components = match.groupValues[1].split('.').map(String::toBigInteger)
            // В отчёте версия без квалификатора (31.1-jre -> 31.1), как в формате авторов набора.
            return NumericVersion(match.groupValues[1], components,Qualifier(rank, word, number))
        }

        fun requireNumeric(value: String): NumericVersion = requireNotNull(parse(value))
    }
}

private val numericVersion = Regex("[0-9]+(?:\\.[0-9]+)*")
private val cveId = Regex("CVE-[0-9]{4}-[0-9]{4,}")
private val severities = setOf("LOW", "MEDIUM", "HIGH", "CRITICAL")

private fun JsonNode.array(field: String): JsonNode = required(field).also { require(it.isArray) }

private fun JsonNode.string(field: String): String = required(field).let { node ->
    requireNotNull(node.textValue()).also { require(it.isNotBlank()) }
}

private fun JsonNode.boolean(field: String): Boolean = required(field).let { node ->
    require(node.isBoolean)
    node.booleanValue()
}
