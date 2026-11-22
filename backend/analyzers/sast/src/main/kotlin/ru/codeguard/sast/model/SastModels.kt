package ru.codeguard.sast.model

/**
 * Результат SAST в форме contracts/finding.schema.json (поля SAST-находки и $defs/coverage).
 * Когда у C появится общий класс находки (модуль report), здесь останется только адаптер.
 */

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }

enum class CoverageStatus { COMPLETE, PARTIAL, FAILED }

/** Место в исходнике. Строки с 1, включительно; endLine только если больше line. */
data class Location(
    val path: String,
    val line: Int,
    val endLine: Int? = null,
    val note: String? = null,
)

data class SastFinding(
    val sastClass: String,
    val rule: String,
    val severity: Severity,
    val path: String,
    val line: Int,
    val endLine: Int?,
    val title: String,
    val description: String,
    val remediation: String,
    /** Цепочка доказательства: источник → преобразования → сток / правило. */
    val evidence: List<Location>,
    /** Нормализованный фрагмент кода для отпечатка находки. */
    val fragment: String,
)

data class SkippedFile(val path: String, val reason: String, val line: Int? = null)

/** Что не удалось установить: поток ушёл в неизвестный вызов, путь маршрута не вычислен и т. п. */
data class Unresolved(val kind: String, val path: String, val line: Int?, val reason: String, val subject: String? = null) {
    /**
     * Значимое: правило не смогло решить, попадают ли данные запроса в опасный сток (непройденный вызов на пути потока,
     * упавшее правило). Только оно понижает покрытие до PARTIAL; прочее (напр. маршрут без вычисленного пути) информационное.
     */
    val significant: Boolean get() = kind in SIGNIFICANT_KINDS

    companion object {
        val SIGNIFICANT_KINDS = setOf("taint-call", "rule-error", "model", "rule-limit")
    }
}

/** Проверенное и отклонённое безопасное место с причиной. */
data class Dismissed(val rule: String, val path: String, val line: Int?, val reason: String)

data class SastCoverage(
    val status: CoverageStatus,
    val filesAnalyzed: Int,
    val filesSkipped: List<SkippedFile>,
    val rulesApplied: List<String>,
    val unresolved: List<Unresolved>,
    val dismissed: List<Dismissed>,
)

data class SastResult(val findings: List<SastFinding>, val coverage: SastCoverage)

/** Коды классов SAST из эталона авторов набора. */
object SastClass {
    const val SQL_INJECTION = "sql-injection"
    const val TLS_VERIFICATION = "tls-verification"
    const val CREDENTIALED_CORS = "credentialed-cors"
    const val ROUTE_AUTHORIZATION = "route-authorization"
    const val OBJECT_AUTHORIZATION = "object-authorization"
}
