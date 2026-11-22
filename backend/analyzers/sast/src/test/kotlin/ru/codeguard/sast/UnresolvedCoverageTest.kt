package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.CoverageStatus
import ru.codeguard.sast.model.Unresolved
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.rules.RuleContext
import ru.codeguard.sast.rules.SastRule
import kotlin.test.assertEquals

/** Значимое unresolved (поток ушёл в непройденный вызов) понижает покрытие до PARTIAL; информационное — нет. */
class UnresolvedCoverageTest {
    private fun rule(kind: String) = object : SastRule {
        override val id = "t"
        override fun check(ctx: RuleContext) {
            ctx.unresolved += Unresolved(kind, "A.kt", 3, "причина")
        }
    }

    private val ok = object : SastRule {
        override val id = "ok"
        override fun check(ctx: RuleContext) {}
    }

    private fun status(kind: String) =
        SastAnalyzer(listOf(rule(kind), ok)).analyze(SastProject(emptyList(), emptyMap(), emptyList())).coverage.status

    @Test
    fun taintCallLowersCoverage() = assertEquals(CoverageStatus.PARTIAL, status("taint-call"))

    @Test
    fun informationalUnresolvedKeepsComplete() = assertEquals(CoverageStatus.COMPLETE, status("library-call"))
}
