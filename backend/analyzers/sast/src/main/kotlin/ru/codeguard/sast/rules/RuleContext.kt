package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.psi.KtNamedFunction
import ru.codeguard.sast.index.FunctionRef
import ru.codeguard.sast.index.ProjectIndex
import ru.codeguard.sast.model.Dismissed
import ru.codeguard.sast.model.Location
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Unresolved
import ru.codeguard.sast.project.KotlinSource
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.spring.Endpoint
import ru.codeguard.sast.spring.SecurityRule
import ru.codeguard.sast.spring.Table
import ru.codeguard.sast.spring.extractEndpoints
import ru.codeguard.sast.spring.extractSecurityChains
import ru.codeguard.sast.spring.extractTables
import ru.codeguard.sast.taint.TaintEngine

/** Правило SAST: один класс проблемы, одна реализация. Новое правило = новый класс + регистрация в SastAnalyzer. */
interface SastRule {
    val id: String
    fun check(ctx: RuleContext)
}

/** Общие факты о проекте, вычисляемые один раз на запуск, и накопители результата. */
class RuleContext(val project: SastProject) {
    val index = ProjectIndex(project)
    val taint = TaintEngine(index)
    val endpoints: List<Endpoint> = extractEndpoints(index)
    /** Обработчики Kafka/RabbitMQ/JMS — внешние источники данных без HTTP-пути. */
    val messageHandlers: List<Endpoint> = ru.codeguard.sast.spring.extractMessageHandlers(index)
    val graphqlEndpoints: List<Endpoint> = ru.codeguard.sast.spring.extractGraphqlEndpoints(index)
    val securityChains: List<List<SecurityRule>> = extractSecurityChains(index)
    val tables: Map<String, Table> = extractTables(index)

    val findings = mutableListOf<SastFinding>()
    val unresolved = mutableListOf<Unresolved>()
    val dismissed = mutableListOf<Dismissed>()

    fun ref(e: Endpoint) = FunctionRef(e.fn, e.file)

    fun unresolved(kind: String, loc: Location, reason: String, subject: String? = null) {
        val u = Unresolved(kind, loc.path, loc.line, reason, subject)
        if (u !in unresolved) unresolved += u
    }

    fun dismiss(rule: String, loc: Location, reason: String) {
        val d = Dismissed(rule, loc.path, loc.line, reason)
        if (d !in dismissed) dismissed += d
    }
}

/** Строка объявления функции — по имени, а не по аннотациям над ней. */
fun KotlinSource.funLine(fn: KtNamedFunction): Int = line(fn.nameIdentifier ?: fn.funKeyword ?: fn)

/**
 * Диапазон находки: от [from] до [to] включительно, не длиннее 15 строк (ограничение формата).
 * Если участок длиннее — оставляем последние 15 строк, где находится сток.
 */
fun range(from: Int, to: Int): Pair<Int, Int?> {
    val start = minOf(from, to)
    val end = maxOf(from, to)
    val clampedStart = if (end - start > 14) end - 14 else start
    return clampedStart to (if (end > clampedStart) end else null)
}

fun KotlinSource.rangeOf(vararg elements: PsiElement): Pair<Int, Int?> {
    val lines = elements.flatMap { listOf(line(it), endLine(it)) }
    return range(lines.min(), lines.max())
}
