package ru.codeguard.ai.model

/**
 * Вход AI-слоя — находки в форме contracts/finding.schema.json (то, что выдали анализаторы).
 * Выход — поля `ai` у находок и раздел `ai` отчёта той же схемы.
 * Набор находок определяют анализаторы: AI-слой не добавляет и не удаляет находки.
 */

data class AiLocation(val path: String, val line: Int, val endLine: Int? = null, val note: String? = null)

data class AiFinding(
    val id: String,
    val category: String,                 // SECRET | SAST | SCA
    val findingClass: String? = null,      // password, sql-injection, …
    val severity: String,                 // LOW | MEDIUM | HIGH | CRITICAL
    val path: String,
    val line: Int? = null,
    val endLine: Int? = null,
    val title: String? = null,
    val description: String? = null,
    val remediation: String? = null,
    val evidence: List<AiLocation> = emptyList(),
    /** Только SECRET: маска. Сырого значения в AI-слое нет и быть не может. */
    val secretMasked: String? = null,
    val group: String? = null,
    val artifact: String? = null,
    val version: String? = null,
    val advisoryId: String? = null,
    val fixedVersions: List<String> = emptyList(),
)

enum class AiFindingStatus { OK, NOT_RECEIVED, REJECTED_BY_VALIDATOR }

/** Поле `ai` находки — заполняется только после валидатора. */
data class FindingAi(
    val status: AiFindingStatus,
    val explanation: String? = null,
    val impact: String? = null,
    val fixSteps: List<String> = emptyList(),
    val fixExample: String? = null,
    /** Детерминированная рекомендация SCA: версия из fixedVersions справочника, а не из ответа модели. */
    val recommendedVersion: String? = null,
    val usefulnessChecks: Map<String, Boolean> = emptyMap(),
    /** Почему объяснения нет или оно отклонено — для интерфейса и отчёта. */
    val reason: String? = null,
)

enum class AiReportStatus { OK, PARTIAL, NOT_RECEIVED }

/** Счётчики валидатора — идут в отчёт и на слайд. */
data class ValidatorStats(
    var responses: Int = 0,
    var schemaFailures: Int = 0,
    var rejectedFindingRefs: Int = 0,
    var rejectedCves: Int = 0,
    var rejectedLocations: Int = 0,
    /** SCA: версии, которых нет в справочнике/находке (модель пыталась предложить свою). */
    var rejectedVersions: Int = 0,
    /** Объяснения, в которых модель оспаривала находку. */
    var rejectedDisputes: Int = 0,
    /** Объяснения, отклонённые как возможный результат prompt injection (оспаривание находки, «игнорируй инструкции» и т. п.). */
    var injectionSuspected: Int = 0,
    var retries: Int = 0,
    var cacheHits: Int = 0,
)

/** Связанные находки, которые вместе образуют одну историю риска (например, открытый маршрут + IDOR). */
data class AiGroup(val title: String, val findingIds: List<String>, val story: String)

data class ReportAi(
    val status: AiReportStatus,
    val provider: String?,
    val model: String?,
    val summary: String?,
    val priorities: List<String>,
    val groups: List<AiGroup>,
    val validator: ValidatorStats,
    /** Явная причина, если объяснения не получены (LLM недоступна, ответ не прошёл проверку). */
    val reason: String? = null,
)

/** Строка таблицы «оценка полезности рекомендаций» для слайда. */
data class UsefulnessSummary(
    val recommendations: Int,
    val withFixExample: Int,
    val fixParses: Int,
    val fixPatternOk: Int,
    val rerunClean: Int,
    val scaTargetSafe: Int,
    val scaTotal: Int,
)

data class AiResult(
    val findings: Map<String, FindingAi>,
    val report: ReportAi,
    val usefulness: UsefulnessSummary,
)
