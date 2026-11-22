package ru.codeguard.sast

import ru.codeguard.sast.model.CoverageStatus
import ru.codeguard.sast.model.SastCoverage
import ru.codeguard.sast.model.SastResult
import ru.codeguard.sast.model.SkippedFile
import ru.codeguard.sast.model.Unresolved
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.rules.CredentialedCorsRule
import ru.codeguard.sast.rules.ObjectAuthorizationRule
import ru.codeguard.sast.rules.RouteAuthorizationRule
import ru.codeguard.sast.rules.RuleContext
import ru.codeguard.sast.rules.SastRule
import ru.codeguard.sast.rules.SqlInjectionRule
import ru.codeguard.sast.rules.TlsVerificationRule

/**
 * Точка входа SAST: проект → находки + покрытие.
 * Детерминизм: находки сортируются (путь, строка, класс) и дедуплицируются; одинаковый вход — одинаковый результат.
 * Неизвестное — не ноль: ошибка разбора файла или падение правила дают PARTIAL с причиной, а не «чисто».
 */
class SastAnalyzer(private val rules: List<SastRule> = DEFAULT_RULES) {

    fun analyze(project: SastProject): SastResult {
        val ctx = try {
            RuleContext(project)
        } catch (e: Exception) {
            return SastResult(
                emptyList(),
                SastCoverage(CoverageStatus.FAILED, 0, emptyList(), emptyList(),
                    listOf(Unresolved("model", "", null, "Не удалось построить модель проекта: ${e.message}")), emptyList()),
            )
        }
        val failedRules = mutableListOf<String>()
        for (rule in rules) {
            try {
                rule.check(ctx)
            } catch (e: Exception) {
                failedRules += rule.id
                ctx.unresolved += Unresolved("rule-error", "", null, "Правило ${rule.id} завершилось ошибкой: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
        val skipped = project.parseErrors.groupBy { it.path }.map { (path, errs) ->
            SkippedFile(path, "Ошибка разбора Kotlin: ${errs.first().message}", errs.first().line)
        }
        val findings = ctx.findings
            .distinctBy { listOf(it.sastClass, it.path, it.line, it.endLine) }
            .sortedWith(compareBy({ it.path }, { it.line }, { it.endLine ?: it.line }, { it.sastClass }))
        val status = when {
            failedRules.size == rules.size && rules.isNotEmpty() -> CoverageStatus.FAILED
            failedRules.isNotEmpty() || skipped.isNotEmpty() || ctx.unresolved.any { it.significant } -> CoverageStatus.PARTIAL
            else -> CoverageStatus.COMPLETE
        }
        return SastResult(
            findings,
            SastCoverage(
                status = status,
                filesAnalyzed = project.kotlin.size - skipped.size,
                filesSkipped = skipped,
                rulesApplied = rules.map { it.id }.filter { it !in failedRules },
                unresolved = ctx.unresolved.sortedWith(compareBy({ it.path }, { it.line ?: 0 }, { it.reason })),
                dismissed = ctx.dismissed.sortedWith(compareBy({ it.path }, { it.line ?: 0 }, { it.rule })),
            ),
        )
    }

    companion object {
        /** Версия набора правил SAST — входит в rulesVersion отчёта. */
        const val RULES_VERSION = "sast-1"

        val DEFAULT_RULES: List<SastRule> = listOf(
            SqlInjectionRule(),
            TlsVerificationRule(),
            CredentialedCorsRule(),
            RouteAuthorizationRule(),
            ObjectAuthorizationRule(),
        )
    }
}
