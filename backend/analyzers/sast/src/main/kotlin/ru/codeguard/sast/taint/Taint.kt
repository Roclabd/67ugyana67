package ru.codeguard.sast.taint

import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockStringTemplateEntry
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtReturnExpression
import org.jetbrains.kotlin.psi.KtSafeQualifiedExpression
import org.jetbrains.kotlin.psi.KtSimpleNameStringTemplateEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.KtThisExpression
import ru.codeguard.sast.index.FunctionRef
import ru.codeguard.sast.index.ProjectIndex
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.index.receiver
import ru.codeguard.sast.model.Location

/** След распространения: от источника через присваивания и вызовы к текущему месту. */
typealias Trace = List<Location>

/**
 * Лёгкий taint-анализ без разрешения типов.
 * Распространение: локальные val/var, присваивания, строковые шаблоны, «+», format, buildString,
 * вызовы функций проекта (до [maxDepth] уровней). Нейтрализация: приведение к числу/UUID/булеву и
 * получение длины/размера — после них значение не может нести SQL-текст.
 */
class TaintEngine(private val index: ProjectIndex, private val maxDepth: Int = 5) {

    /** Имена, помеченные внутри функции, с их следами. Итерация до неподвижной точки (порядок присваиваний не важен). */
    fun localTaint(fn: KtNamedFunction, seeds: Map<String, Trace>): Map<String, Trace> {
        val file = index.fileOf(fn) ?: return seeds
        val guarded = whitelistGuarded(fn)
        val tainted = seeds.filterKeys { it !in guarded }.toMutableMap()
        val props = PsiTreeUtil.findChildrenOfType(fn, KtProperty::class.java).filter { it.isLocal }
        val assigns = PsiTreeUtil.findChildrenOfType(fn, KtBinaryExpression::class.java).filter { it.operationToken == KtTokens.EQ || it.operationToken == KtTokens.PLUSEQ }
        var changed = true
        while (changed) {
            changed = false
            for (p in props) {
                val name = p.name ?: continue
                if (name in tainted) continue
                val t = taintOf(p.initializer, tainted) ?: continue
                tainted[name] = t + file.loc(p, "присваивание $name")
                changed = true
            }
            for (a in assigns) {
                val name = (a.left as? KtNameReferenceExpression)?.getReferencedName() ?: continue
                if (name in tainted) continue
                val t = taintOf(a.right, tainted) ?: continue
                tainted[name] = t + file.loc(a, "присваивание $name")
                changed = true
            }
            // x.let { ... it ... }: неявный параметр лямбды несёт значение получателя
            if ("it" !in tainted) for (call in PsiTreeUtil.findChildrenOfType(fn, KtCallExpression::class.java).filter { it.calleeName in setOf("let", "also", "takeIf", "takeUnless", "run") && it.lambdaArguments.isNotEmpty() }) {
                val t = taintOf(call.receiver, tainted) ?: continue
                tainted["it"] = t + file.loc(call, "лямбда ${call.calleeName} над помеченным значением")
                changed = true
                break
            }
            // StringBuilder: sb.append(x) помечает sb
            for (call in PsiTreeUtil.findChildrenOfType(fn, KtCallExpression::class.java).filter { it.calleeName in setOf("append", "appendLine", "add", "addAll", "put") }) {
                val recv = (call.receiver as? KtNameReferenceExpression)?.getReferencedName() ?: continue
                if (recv in tainted) continue
                val t = call.valueArguments.firstNotNullOfOrNull { taintOf(it.getArgumentExpression(), tainted) } ?: continue
                tainted[recv] = t + file.loc(call, "дописывание в $recv")
                changed = true
            }
        }
        return tainted
    }

    /**
     * Имена, ограниченные белым списком фиксированных строк до использования:
     * require(x in setOf("a", "b")), check(x in ALLOWED), if (x !in ALLOWED) throw/return …
     * После такой проверки значение — одно из известных сервером, а не произвольный текст.
     */
    private fun whitelistGuarded(fn: KtNamedFunction): Set<String> {
        val out = mutableSetOf<String>()
        fun guardedName(cond: KtExpression?, negated: Boolean): String? {
            val bin = cond as? KtBinaryExpression ?: return null
            val op = bin.operationToken
            val ok = (!negated && op == KtTokens.IN_KEYWORD) || (negated && op == KtTokens.NOT_IN)
            if (!ok || !isLiteralCollection(bin.right)) return null
            return (bin.left as? KtNameReferenceExpression)?.getReferencedName()
        }
        for (call in PsiTreeUtil.findChildrenOfType(fn, KtCallExpression::class.java)) {
            if (call.calleeName in setOf("require", "check")) guardedName(call.valueArguments.firstOrNull()?.getArgumentExpression(), false)?.let { out += it }
        }
        for (ifExpr in PsiTreeUtil.findChildrenOfType(fn, org.jetbrains.kotlin.psi.KtIfExpression::class.java)) {
            val then = ifExpr.then ?: continue
            val exits = then is org.jetbrains.kotlin.psi.KtThrowExpression || then is KtReturnExpression ||
                (then as? org.jetbrains.kotlin.psi.KtBlockExpression)?.statements?.lastOrNull().let { it is org.jetbrains.kotlin.psi.KtThrowExpression || it is KtReturnExpression }
            if (exits) guardedName(ifExpr.condition, true)?.let { out += it }
        }
        return out
    }

    /** setOf("a","b") / listOf(...) / arrayOf(...) из строковых литералов или ссылка на такую константу проекта. */
    private fun isLiteralCollection(e: KtExpression?): Boolean {
        val call = when (e) {
            is KtCallExpression -> e
            is KtNameReferenceExpression -> (index.localValInitializer(e.getReferencedName(), e)
                ?: propertyInitializer(e.getReferencedName())) as? KtCallExpression
            else -> null
        } ?: return false
        return call.calleeName in setOf("setOf", "listOf", "arrayOf", "hashSetOf", "mutableSetOf", "linkedSetOf") &&
            call.valueArguments.isNotEmpty() && call.valueArguments.all { index.stringValue(it.getArgumentExpression()) != null }
    }

    private fun propertyInitializer(name: String): KtExpression? =
        index.project.kotlin.asSequence().flatMap { PsiTreeUtil.findChildrenOfType(it.psi, KtProperty::class.java).asSequence() }
            .firstOrNull { !it.isLocal && it.name == name }?.initializer

    /** След, если выражение несёт помеченное значение; null — чисто. */
    fun taintOf(expr: KtExpression?, tainted: Map<String, Trace>): Trace? {
        if (expr == null || tainted.isEmpty()) return null
        val refs = PsiTreeUtil.collectElementsOfType(expr, KtNameReferenceExpression::class.java).toMutableList()
        if (expr is KtNameReferenceExpression) refs += expr
        for (ref in refs) {
            val trace = tainted[ref.getReferencedName()] ?: continue
            if (isNeutralized(ref, expr)) continue
            if (isCalleeOrSelectorName(ref)) continue
            return trace
        }
        return null
    }

    /** Ссылка — имя вызываемой функции или свойства справа от точки, а не переменная. */
    private fun isCalleeOrSelectorName(ref: KtNameReferenceExpression): Boolean {
        val p = ref.parent
        if (p is KtCallExpression && p.calleeExpression == ref) return true
        if ((p is KtDotQualifiedExpression || p is KtSafeQualifiedExpression) && (p as KtExpression).let {
                (it as? KtDotQualifiedExpression)?.selectorExpression == ref || (it as? KtSafeQualifiedExpression)?.selectorExpression == ref
            } && (p as? KtDotQualifiedExpression)?.receiverExpression !is KtThisExpression) return true
        return false
    }

    private fun isNeutralized(ref: KtNameReferenceExpression, root: KtExpression): Boolean {
        var cur: org.jetbrains.kotlin.com.intellij.psi.PsiElement = ref
        while (cur != root && cur.parent != null) {
            val p = cur.parent
            if ((p is KtDotQualifiedExpression && p.receiverExpression == cur) || (p is KtSafeQualifiedExpression && p.receiverExpression == cur)) {
                val sel = (p as? KtDotQualifiedExpression)?.selectorExpression ?: (p as? KtSafeQualifiedExpression)?.selectorExpression
                val name = (sel as? KtCallExpression)?.calleeName ?: (sel as? KtNameReferenceExpression)?.getReferencedName()
                if (name in NEUTRAL_SELECTORS) return true
                if (sel is KtCallExpression && returnsConstant(sel)) return true
            }
            if (p is org.jetbrains.kotlin.psi.KtValueArgument) {
                val call = PsiTreeUtil.getParentOfType(p, KtCallExpression::class.java)
                val qualified = call?.parent as? KtDotQualifiedExpression
                val fq = (qualified?.receiverExpression?.text?.let { "$it." } ?: "") + (call?.calleeName ?: "")
                if (fq in NEUTRAL_CALLS || call?.calleeName in NEUTRAL_CALLS) return true
            }
            if (p is KtLambdaExpression) return false
            cur = p
        }
        return false
    }

    /**
     * Вызов функции проекта (в т. ч. extension), чьё тело — только литералы: `filter.toNamedWhere()`
     * возвращает константный текст и не переносит данные получателя. Все кандидаты по имени должны быть такими.
     */
    private fun returnsConstant(call: KtCallExpression): Boolean {
        val name = call.calleeName ?: return false
        val candidates = index.functions.filter { it.name == name && it.fn.hasBody() }
        if (candidates.isEmpty()) return false
        return candidates.all { c ->
            val body = c.fn.bodyExpression ?: return@all false
            PsiTreeUtil.collectElementsOfType(body, KtNameReferenceExpression::class.java).isEmpty() &&
                PsiTreeUtil.collectElementsOfType(body, KtStringTemplateExpression::class.java)
                    .all { t -> t.entries.all { it is KtLiteralStringTemplateEntry || it is KtEscapeStringTemplateEntry } }
        }
    }

    // ───────────── Межпроцедурный обход ─────────────

    class Visit(val ref: FunctionRef, val tainted: Map<String, Trace>, val callChain: List<Location>)

    /**
     * Обходит функцию и функции проекта, в которые уходят помеченные значения, вызывая [visitor] для каждой.
     * Возвращает места, где поток ушёл туда, куда анализ не смог пойти (для coverage.unresolved).
     */
    fun walk(entry: FunctionRef, seeds: Map<String, Trace>, visitor: (Visit) -> Unit): List<Triple<Location, String, String>> {
        val unresolved = mutableListOf<Triple<Location, String, String>>()
        val seen = mutableSetOf<Pair<KtNamedFunction, Set<String>>>()
        fun go(ref: FunctionRef, seedsHere: Map<String, Trace>, chain: List<Location>, depth: Int) {
            if (!seen.add(ref.fn to seedsHere.keys)) return
            val tainted = localTaint(ref.fn, seedsHere)
            visitor(Visit(ref, tainted, chain))
            for (call in PsiTreeUtil.findChildrenOfType(ref.fn, KtCallExpression::class.java)) {
                val taintedArgs = call.valueArguments.mapIndexedNotNull { i, a -> taintOf(a.getArgumentExpression(), tainted)?.let { Triple(i, a, it) } }
                if (taintedArgs.isEmpty()) continue
                val recvType = receiverType(call)
                val targets = index.resolveCall(call, recvType).filter { it.fn != ref.fn }
                val callLoc = ref.file.loc(call, "вызов ${call.calleeName}()")
                if (targets.isEmpty()) {
                    if (recvType != null && recvType in index.classes) {
                        // Метод не объявлен нигде в проекте — унаследован от фреймворка (напр. JpaRepository.findAll): информационно.
                        val kind = if (index.declaresFunction(call.calleeName ?: "")) "taint-call" else "framework-call"
                        unresolved += Triple(callLoc, kind, "Поток данных уходит в ${recvType}.${call.calleeName}() — реализация не найдена")
                    }
                    continue
                }
                if (depth >= maxDepth) {
                    unresolved += Triple(callLoc, "taint-call", "Глубина межпроцедурного анализа исчерпана на ${call.calleeName}()")
                    continue
                }
                for (t in targets) {
                    val params = t.fn.valueParameters
                    val mapped = mutableMapOf<String, Trace>()
                    for ((i, a, trace) in taintedArgs) {
                        val named = a.getArgumentName()?.asName?.asString()
                        val p = if (named != null) params.firstOrNull { it.name == named } else params.getOrNull(i) ?: params.lastOrNull()?.takeIf { it.isVarArg }
                        p?.name?.let { mapped[it] = trace + callLoc }
                    }
                    if (mapped.isNotEmpty()) go(t, mapped, chain + callLoc, depth + 1)
                }
            }
        }
        go(entry, seeds, emptyList(), 0)
        return unresolved
    }

    fun receiverType(call: KtCallExpression): String? = when (val r = call.receiver) {
        is KtNameReferenceExpression -> index.declaredType(r.getReferencedName(), call)
        is KtDotQualifiedExpression -> if (r.receiverExpression is KtThisExpression) (r.selectorExpression as? KtNameReferenceExpression)?.let { index.declaredType(it.getReferencedName(), call) } else null
        else -> null
    }

    companion object {
        val NEUTRAL_SELECTORS = setOf(
            "length", "size", "isEmpty", "isNotEmpty", "isBlank", "isNotBlank", "count", "hashCode",
            "toInt", "toLong", "toShort", "toByte", "toDouble", "toFloat", "toBigDecimal", "toBigInteger", "toBoolean",
            "toIntOrNull", "toLongOrNull", "toDoubleOrNull", "toBooleanStrict",
        )
        val NEUTRAL_CALLS = setOf(
            "UUID.fromString", "Integer.parseInt", "Integer.valueOf", "Long.parseLong", "Long.valueOf",
            "parseInt", "parseLong", "requireNumeric", "enumValueOf", "valueOf",
        )
    }
}

// ───────────── SQL ─────────────

/** Методы JDBC / JPA / JdbcClient / R2DBC, первый аргумент которых — текст SQL/JPQL. */
val SQL_SINKS = setOf(
    "query", "queryForList", "queryForObject", "queryForMap", "queryForRowSet", "queryForStream", "queryForLong", "queryForInt",
    "update", "batchUpdate", "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch",
    "prepareStatement", "prepareCall", "createQuery", "createNativeQuery", "createStatement", "sql",
    // Hibernate, jOOQ, Exposed
    "createSQLQuery", "fetch", "fetchOne", "fetchAny", "fetchMany", "fetchLazy", "fetchSingle", "resultQuery", "exec",
)

private val SQL_WORDS = Regex("""\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|merge\s+into|call\s+\w+|from\s+\w+|where)\b""", RegexOption.IGNORE_CASE)

/**
 * Скелет SQL-выражения: литералы как есть, неизвестные части — «⟨выражение⟩».
 * Разворачивает локальные val, константы проекта, «+», шаблоны, buildString/append и String.format.
 */
fun sqlSkeleton(index: ProjectIndex, expr: KtExpression?, depth: Int = 0): String {
    if (expr == null || depth > 6) return "⟨?⟩"
    index.stringValue(expr)?.let { return it }
    return when (expr) {
        is KtParenthesizedExpression -> sqlSkeleton(index, expr.expression, depth + 1)
        is KtStringTemplateExpression -> expr.entries.joinToString("") { e ->
            when (e) {
                is KtLiteralStringTemplateEntry -> e.text
                is KtEscapeStringTemplateEntry -> e.unescapedValue
                is KtSimpleNameStringTemplateEntry -> index.stringValue(e.expression) ?: "⟨${e.expression?.text}⟩"
                is KtBlockStringTemplateEntry -> index.stringValue(e.expression) ?: "⟨${e.expression?.text}⟩"
                else -> "⟨?⟩"
            }
        }
        is KtBinaryExpression -> if (expr.operationToken == KtTokens.PLUS) sqlSkeleton(index, expr.left, depth + 1) + sqlSkeleton(index, expr.right, depth + 1) else "⟨${expr.text}⟩"
        is KtNameReferenceExpression -> index.localValInitializer(expr.getReferencedName(), expr)?.let { sqlSkeleton(index, it, depth + 1) } ?: "⟨${expr.text}⟩"
        is KtDotQualifiedExpression -> {
            val sel = expr.selectorExpression as? KtCallExpression
            when (sel?.calleeName) {
                "format" -> sqlSkeleton(index, expr.receiverExpression, depth + 1) // "...%s".format(x)
                "trimIndent", "trimMargin", "trim", "replace", "lowercase", "uppercase" -> sqlSkeleton(index, expr.receiverExpression, depth + 1)
                "toString" -> sqlSkeleton(index, expr.receiverExpression, depth + 1)
                "let", "run", "also", "apply", "takeIf" -> {
                    // name.let { "... $it" }: текст запроса — последнее выражение лямбды
                    val last = (sel?.lambdaArguments?.firstOrNull()?.getLambdaExpression()?.bodyExpression?.statements?.lastOrNull())
                    if (last != null) sqlSkeleton(index, last, depth + 1) else "⟨${expr.text}⟩"
                }
                else -> if (expr.receiverExpression.text == "String" && sel?.calleeName == "format") sqlSkeleton(index, sel.valueArguments.firstOrNull()?.getArgumentExpression(), depth + 1) else "⟨${expr.text}⟩"
            }
        }
        is KtCallExpression -> when (expr.calleeName) {
            "buildString" -> PsiTreeUtil.findChildrenOfType(expr, KtCallExpression::class.java)
                .filter { it.calleeName == "append" || it.calleeName == "appendLine" }
                .joinToString("") { sqlSkeleton(index, it.valueArguments.firstOrNull()?.getArgumentExpression(), depth + 1) }
            "format" -> sqlSkeleton(index, expr.valueArguments.firstOrNull()?.getArgumentExpression(), depth + 1)
            else -> "⟨${expr.text}⟩"
        }
        else -> "⟨${expr.text}⟩"
    }
}

fun looksLikeSql(skeleton: String): Boolean = SQL_WORDS.containsMatchIn(skeleton)

/** Аргумент SQL-текста у вызова-стока: именованный sql/query/qlString или первый позиционный. */
fun sqlArgument(call: KtCallExpression): KtExpression? {
    call.valueArguments.firstOrNull { it.getArgumentName()?.asName?.asString() in setOf("sql", "query", "qlString", "sqlString") }
        ?.let { return it.getArgumentExpression() }
    return call.valueArguments.firstOrNull { it.getArgumentName() == null }?.getArgumentExpression()
}
