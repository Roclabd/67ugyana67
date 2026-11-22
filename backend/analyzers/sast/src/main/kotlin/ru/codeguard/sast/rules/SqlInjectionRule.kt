package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import ru.codeguard.sast.index.FunctionRef
import ru.codeguard.sast.index.strings
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.index.normalizedFragment
import ru.codeguard.sast.model.Location
import ru.codeguard.sast.model.SastClass
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Severity
import ru.codeguard.sast.spring.ParamSource
import ru.codeguard.sast.taint.SQL_SINKS
import ru.codeguard.sast.taint.Trace
import ru.codeguard.sast.taint.looksLikeSql
import ru.codeguard.sast.taint.sqlArgument
import ru.codeguard.sast.taint.sqlSkeleton

private val MYBATIS_SQL = setOf("Select", "Update", "Delete", "Insert")

/** Типы параметров, которые Spring приводит до вызова метода: в SQL-текст они не принесут кавычек и операторов. */
val NON_INJECTABLE_TYPES = setOf(
    "Long", "Int", "Short", "Byte", "Double", "Float", "Boolean", "UUID", "BigDecimal", "BigInteger",
    "LocalDate", "LocalDateTime", "Instant", "OffsetDateTime", "ZonedDateTime", "Char",
)

/** Объект запроса целиком: request.getParameter/getHeader/getQueryString несут данные клиента. */
val REQUEST_OBJECT_TYPES = setOf("HttpServletRequest", "ServletRequest", "WebRequest", "NativeWebRequest", "ServerHttpRequest", "ServerRequest")

private val UNTRUSTED = setOf(
    ParamSource.REQUEST_PARAM, ParamSource.PATH_VARIABLE, ParamSource.REQUEST_BODY, ParamSource.REQUEST_HEADER,
    ParamSource.COOKIE, ParamSource.MODEL_ATTRIBUTE, ParamSource.IMPLICIT,
)

/** Получатели, у которых методы-стоки точно исполняют SQL/JPQL, даже если текст запроса не распознан. */
private val DB_TYPES = setOf(
    "JdbcTemplate", "NamedParameterJdbcTemplate", "JdbcOperations", "NamedParameterJdbcOperations", "JdbcClient",
    "EntityManager", "Connection", "Statement", "DatabaseClient", "Session", "DSLContext",
)

/**
 * sql-injection: данные запроса (источник) попадают в текст SQL/JPQL (сток) без параметризации.
 * Источник — параметр обработчика контроллера; распространение — TaintEngine (локально и в функции проекта);
 * сток — первый аргумент методов JDBC/JPA. Значения, переданные отдельными аргументами, — параметризация (dismissed).
 */
class SqlInjectionRule : SastRule {
    override val id = "sast.sql.taint-to-query"

    override fun check(ctx: RuleContext) {
        val reported = mutableSetOf<KtCallExpression>()
        val reportedMappers = mutableSetOf<KtNamedFunction>()
        for (ep in ctx.endpoints + ctx.messageHandlers + ctx.graphqlEndpoints) {
            val seeds: Map<String, Trace> = ep.params
                .filter { (it.source in UNTRUSTED && it.type !in NON_INJECTABLE_TYPES && !isEnumType(ctx, it.type)) || it.type in REQUEST_OBJECT_TYPES }
                .associate { p -> p.name to listOf(ep.file.loc(p.param, "источник: ${sourceLabel(p.source)} ${p.name}")) }
            if (seeds.isEmpty()) continue

            val lost = ctx.taint.walk(ctx.ref(ep), seeds) { visit ->
                val file = visit.ref.file
                myBatisSubstitution(ctx, visit.ref, visit.tainted)?.let { (anno, trace) ->
                    if (reportedMappers.add(visit.ref.fn)) {
                        val (line, endLine) = range(file.funLine(visit.ref.fn), file.line(anno))
                        val sinkName = "${visit.ref.owner?.name ?: "Mapper"}.${visit.ref.name}"
                        ctx.findings += SastFinding(
                            sastClass = SastClass.SQL_INJECTION,
                            rule = id,
                            severity = Severity.HIGH,
                            path = file.path,
                            line = line,
                            endLine = endLine,
                            title = "SQL-инъекция",
                            description = "Значение из запроса (${trace.first().note?.removePrefix("источник: ")}) подставляется в SQL MyBatis через `\${...}` " +
                                "(строковая подстановка без экранирования) в $sinkName().",
                            remediation = "Использовать `#{...}` (параметр запроса) вместо `\${...}`; динамические идентификаторы — только из белого списка.",
                            evidence = dedupe(trace + visit.callChain + file.loc(anno, "сток: `\${}` в аннотации SQL $sinkName()")),
                            fragment = normalizedFragment(anno),
                        )
                    }
                }
                for (call in PsiTreeUtil.findChildrenOfType(visit.ref.fn, KtCallExpression::class.java)) {
                    if (call.calleeName !in SQL_SINKS) continue
                    val sqlArg = sqlArgument(call) ?: continue
                    val skeleton = sqlSkeleton(ctx.index, sqlArg)
                    val recvType = ctx.taint.receiverType(call)
                    val isDb = recvType in DB_TYPES || looksLikeSql(skeleton)
                    if (!isDb) continue
                    val trace = ctx.taint.taintOf(sqlArg, visit.tainted)
                    if (trace == null) {
                        val paramTainted = call.valueArguments.any { a -> a.getArgumentExpression() != sqlArg && ctx.taint.taintOf(a.getArgumentExpression(), visit.tainted) != null }
                        if (paramTainted) ctx.dismiss(id, file.loc(call), "Параметризованный запрос: данные запроса передаются отдельным аргументом, а не в тексте SQL")
                        continue
                    }
                    if (!reported.add(call)) continue
                    val (line, endLine) = range(file.funLine(visit.ref.fn), file.line(sqlArg))
                    val sinkName = (recvType ?: call.parent.text.substringBefore('.')) + "." + call.calleeName
                    val source = trace.first()
                    ctx.findings += SastFinding(
                        sastClass = SastClass.SQL_INJECTION,
                        rule = id,
                        severity = Severity.HIGH,
                        path = file.path,
                        line = line,
                        endLine = endLine,
                        title = "SQL-инъекция",
                        description = "Значение из запроса (${source.note?.removePrefix("источник: ")}) встраивается в текст SQL, " +
                            "который передаётся в $sinkName() без параметризации. Злоумышленник может изменить запрос к базе данных.",
                        remediation = "Использовать плейсхолдер `?` (или именованный параметр) в тексте запроса и передать значение отдельным аргументом $sinkName().",
                        evidence = dedupe(trace + visit.callChain + file.loc(sqlArg, "сток: текст SQL в $sinkName()")),
                        fragment = normalizedFragment(call),
                    )
                }
            }
            lost.forEach { (loc, kind, reason) -> ctx.unresolved(kind, loc, reason) }
        }
    }

    /**
     * MyBatis: @Select/@Update/@Delete/@Insert с `${param}` — строковая подстановка (`#{}` безопасен).
     * Возвращает аннотацию и след, если подставляется помеченный параметр метода.
     */
    private fun myBatisSubstitution(ctx: RuleContext, ref: FunctionRef, tainted: Map<String, Trace>): Pair<KtAnnotationEntry, Trace>? {
        for (anno in ref.fn.annotationEntries) {
            if (anno.shortName?.asString() !in MYBATIS_SQL) continue
            val text = anno.valueArguments.mapNotNull { ctx.index.strings(it.getArgumentExpression()).takeIf { l -> l.isNotEmpty() } }.flatten().joinToString(" ")
            val roots = Regex("""\$\{\s*([A-Za-z_]\w*)""").findAll(text).map { it.groupValues[1] }.toSet()
            for (p in ref.fn.valueParameters) {
                val alias = p.annotationEntries.firstOrNull { it.shortName?.asString() == "Param" }
                    ?.let { ctx.index.strings(it.valueArguments.firstOrNull()?.getArgumentExpression()).firstOrNull() }
                val names = listOfNotNull(p.name, alias)
                if (names.none { it in roots }) continue
                val trace = tainted[p.name ?: continue] ?: continue
                return anno to trace
            }
        }
        return null
    }

    /** Enum из проекта: Spring подставит только константу, значение из белого списка — инъекции нет. */
    private fun isEnumType(ctx: RuleContext, type: String?): Boolean =
        type != null && (ctx.index.classes[type.removeSuffix("?")]?.first as? org.jetbrains.kotlin.psi.KtClass)?.isEnum() == true

    private fun dedupe(locs: List<Location>): List<Location> = locs.distinctBy { Triple(it.path, it.line, it.note) }
}

fun sourceLabel(s: ParamSource): String = when (s) {
    ParamSource.REQUEST_PARAM -> "@RequestParam"
    ParamSource.PATH_VARIABLE -> "@PathVariable"
    ParamSource.REQUEST_BODY -> "@RequestBody"
    ParamSource.REQUEST_HEADER -> "@RequestHeader"
    ParamSource.COOKIE -> "@CookieValue"
    ParamSource.MODEL_ATTRIBUTE -> "@ModelAttribute"
    ParamSource.IMPLICIT -> "параметр запроса"
    ParamSource.IDENTITY -> "пользователь"
    ParamSource.OTHER -> "параметр"
}
