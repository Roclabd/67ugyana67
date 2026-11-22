package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import ru.codeguard.sast.spring.topOfChain
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.index.normalizedFragment
import ru.codeguard.sast.model.Location
import ru.codeguard.sast.model.SastClass
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Severity
import ru.codeguard.sast.spring.Access
import ru.codeguard.sast.spring.Endpoint
import ru.codeguard.sast.spring.ParamSource
import ru.codeguard.sast.spring.effectiveRule
import ru.codeguard.sast.taint.Trace

/**
 * object-authorization (IDOR): объект читается по идентификатору из запроса без проверки владельца.
 *
 * Условия находки (все сразу):
 *  - эндпоинт принимает идентификатор (@PathVariable / @RequestParam …Id, uuid, code, number);
 *  - у эндпоинта нет источника личности, который используется: Principal, Authentication, @AuthenticationPrincipal,
 *    @RequestHeader("Authorization"), SecurityContextHolder; нет @PreAuthorize/@PostAuthorize с проверкой владельца;
 *  - идентификатор доходит (taint, через сервисы до 3 уровней) до чтения данных: SQL с WHERE по id или Spring Data findById;
 *  - у таблицы/сущности есть owner-колонка (customer_id, user_id, owner_id…), а условие запроса её не содержит;
 *  - маршрут доступен обычному вошедшему пользователю (authenticated или клиентская роль). permitAll — это route-authorization,
 *    сотрудничьи роли (ADMIN, MECHANIC, MANAGER…) видят все записи по замыслу.
 * Основное место — функция, где происходит чтение (как в эталоне: репозиторий), эндпоинт — в evidence.
 */
class ObjectAuthorizationRule : SastRule {
    override val id = "sast.idor.read-by-id-without-owner"

    private val idName = Regex("""(?i)(^id$|id$|uuid$|^code$|code$|number$|^key$|slug$)""")
    private val strictIdName = Regex("""(^id$|Id$|_id$|ID$|(?i)uuid$|(?i)guid$)""")
    /** Служебные роли — общие названия сотрудников; скрытая вариация может назвать их по-своему (не только как в учебном проекте). */
    private val staffRole = Regex(
        """(?i)(admin|staff|mechanic|manager|operator|support|employee|internal|moderator|service|system|auditor|""" +
            """technician|engineer|clerk|dispatcher|worker|master|accountant|warehouse|backoffice|superuser|root)""",
    )
    /**
     * Признаки проверки владельца в коде: исключения доступа, сравнение owner-поля (в любом написании —
     * ownerId, .owner, row["customer_id"]) или сравнение с личностью (authentication.name, principal.name).
     */
    private val ownerCheck = Regex(
        """(?i)(SecurityContextHolder|AccessDenied|NotOwner|IsNotOwner|Forbidden|checkOwner|assertOwner|requireOwner|verifyOwner|""" +
            """(owner|customer|user|client|account)_?id\b["'\]\)]*\s*[!=]=|\.owner\w*\s*[!=]=|""" +
            """[!=]=\s*[\w.\[\]"']*(owner|customer_?id|user_?id)\b|""" +
            """[!=]=\s*[\w.]*(authentication|principal|auth)\.name|(authentication|principal|auth)\.name\s*[!=]=)""",
    )

    /**
     * Выводит owner-колонки из самого проекта: если запрос к таблице сравнивает колонку со значением,
     * пришедшим от личности (principal.name, authentication.name), эта колонка — владелец записи.
     */
    private fun inferOwnerColumns(ctx: RuleContext) {
        for (ep in ctx.endpoints) {
            val identitySeeds: Map<String, Trace> = ep.params.filter { it.source == ParamSource.IDENTITY }
                .associate { p -> p.name to listOf(ep.file.loc(p.param, "личность пользователя: ${p.name}")) }
            if (identitySeeds.isEmpty()) continue
            val origins = identitySeeds.values.map { it.first() }.toSet()
            ctx.taint.walk(ctx.ref(ep), identitySeeds) { visit ->
                for (da in dataAccessesIn(ctx, visit.ref)) {
                    val sqlArg = da.sqlArg ?: continue
                    val sql = ru.codeguard.sast.taint.sqlSkeleton(ctx.index, sqlArg).replace(Regex("\\s+"), " ")
                    val chainCalls = PsiTreeUtil.findChildrenOfType(topOfChain(da.call), KtCallExpression::class.java) + da.call
                    fun fromIdentity(e: org.jetbrains.kotlin.psi.KtExpression?) = e != null && ctx.taint.taintOf(e, visit.tainted)?.firstOrNull() in origins
                    val bound = mutableSetOf<String>() // имена параметров, значение которых — личность
                    for (c in chainCalls) {
                        val args = c.valueArguments.mapNotNull { it.getArgumentExpression() }
                        // .param("p", x) / addValue("p", x)
                        if (args.size == 2 && ctx.index.stringValue(args[0]) != null && fromIdentity(args[1])) bound += ctx.index.stringValue(args[0])!!
                        for (a in args) for (b in PsiTreeUtil.findChildrenOfType(a, org.jetbrains.kotlin.psi.KtBinaryExpression::class.java) + listOfNotNull(a as? org.jetbrains.kotlin.psi.KtBinaryExpression)) {
                            if (b.operationReference.text == "to") ctx.index.stringValue(b.left)?.let { if (fromIdentity(b.right)) bound += it }
                        }
                    }
                    val cols = mutableSetOf<String>()
                    Regex("""(?:\w+\.)?(\w+)\s*=\s*:(\w+)""").findAll(sql).forEach { m -> if (m.groupValues[2] in bound) cols += m.groupValues[1].lowercase() }
                    val valueArgs = chainCalls.flatMap { c -> c.valueArguments.mapNotNull { it.getArgumentExpression() } }.filter { it != sqlArg && !isNonValueArg(it) }
                    Regex("""(?:\w+\.)?(\w+)\s*=\s*\?""").findAll(sql).forEachIndexed { i, m -> if (fromIdentity(valueArgs.getOrNull(i))) cols += m.groupValues[1].lowercase() }
                    if (cols.isNotEmpty()) for (t in da.tables) t.inferredOwners += cols
                }
            }
        }
    }

    override fun check(ctx: RuleContext) {
        inferOwnerColumns(ctx)
        val reported = mutableSetOf<Pair<String, Int>>()
        for (ep in ctx.endpoints + ctx.graphqlEndpoints) {
            // Переменная пути — ссылка на объект по замыслу (/tickets/{code}); параметр запроса — только явный id,
            // иначе это поиск (?ticketCode=…), а не обращение к объекту по идентификатору.
            // Идентификатор может прийти и полем тела запроса (@RequestBody dto -> dto.orderId).
            val dtoIdFields: Map<String, List<String>> = ep.params.filter { it.source == ParamSource.REQUEST_BODY && it.type != null }
                .associate { it.name to dtoIdFields(ctx, it.type!!) }.filterValues { it.isNotEmpty() }
            // Переменная пути с иным именем (/{reservationNo}) — тоже ключ объекта, если ею ищут по производному запросу репозитория
            // (deleteByReservationNo(reservationNo)); проверяется ниже по имени метода.
            val lookupKeys = ep.params.filter { it.source == ParamSource.PATH_VARIABLE && !idName.containsMatchIn(it.name) && it.name.isNotEmpty() }
            val ids = ep.params.filter {
                (it.source == ParamSource.PATH_VARIABLE) ||
                    (it.source in setOf(ParamSource.REQUEST_PARAM, ParamSource.IMPLICIT) && strictIdName.containsMatchIn(it.name)) ||
                    it.name in dtoIdFields
            }
            if (ids.isEmpty()) continue
            val epLoc = ep.file.loc(ep.fn.nameIdentifier ?: ep.fn, "эндпоинт ${ep.methods.joinToString("|").ifEmpty { "ANY" }} ${ep.paths.joinToString()}")

            identityUse(ep)?.let { ctx.dismiss(id, epLoc, it); continue }
            // Личность (Principal, @AuthenticationPrincipal, заголовок Authorization) защищает, только если дошла до аргументов чтения
            // или сравнивается с владельцем загруженной записи; простое получение или журналирование — не проверка.
            val identitySeeds: Map<String, Trace> = ep.params.filter { it.source == ParamSource.IDENTITY }
                .associate { p -> p.name to listOf(ep.file.loc(p.param, "личность пользователя: ${p.name}")) }
            val identityOrigins = identitySeeds.values.map { it.first() }.toSet()
            ep.methodSecurity.firstOrNull { Regex("""(?i)(principal|authentication|returnObject|#\w+)""").containsMatchIn(it) }
                ?.let { ctx.dismiss(id, epLoc, "Доступ проверяется аннотацией $it"); continue }
            accessExclusion(ctx, ep)?.let { ctx.dismiss(id, epLoc, it); continue }

            val idSeeds: Map<String, Trace> = ids.associate { p -> p.name to listOf(ep.file.loc(p.param, "идентификатор из запроса: ${p.name}")) }
            val idOrigins = idSeeds.values.map { it.first() }.toSet()
            val lookupOrigins = lookupKeys.mapNotNull { idSeeds[it.name]?.first() }.toSet()
            val dtoOrigins = dtoIdFields.keys.mapNotNull { idSeeds[it]?.first() }.toSet()
            val writeOnly = ep.methods.isNotEmpty() && ep.methods.all { it in setOf("PUT", "PATCH", "DELETE") }
            // Остальные данные запроса тоже помечаем: owner-фильтр, значение которого прислал клиент, ничего не защищает.
            val otherSeeds = ep.params.filter { it !in ids && it.source in setOf(ParamSource.REQUEST_PARAM, ParamSource.IMPLICIT, ParamSource.REQUEST_BODY, ParamSource.REQUEST_HEADER, ParamSource.PATH_VARIABLE, ParamSource.COOKIE) }
                .associate { p -> p.name to listOf(ep.file.loc(p.param, "значение из запроса: ${p.name}")) }
            val seeds = otherSeeds + idSeeds + identitySeeds
            var ownerChecked: Location? = null
            val candidates = mutableListOf<Pair<DataAccess, List<Location>>>()
            ctx.taint.walk(ctx.ref(ep), seeds) { visit ->
                if (ownerCheck.containsMatchIn(visit.ref.fn.text)) ownerChecked = ownerChecked ?: visit.ref.file.loc(visit.ref.fn.nameIdentifier ?: visit.ref.fn, "проверка владельца")
                if (ownerChecked == null) identityComparison(visit.ref.fn.text, visit.tainted, identityOrigins)?.let { ownerChecked = visit.ref.file.loc(visit.ref.fn.nameIdentifier ?: visit.ref.fn, "личность сравнивается с владельцем") }
                for (da in dataAccessesIn(ctx, visit.ref)) {
                    // Идентификатор — аргумент самого вызова или звена той же цепочки: jdbcClient.sql(…).param("id", id).query()
                    val chainCalls = PsiTreeUtil.findChildrenOfType(topOfChain(da.call), KtCallExpression::class.java) + da.call
                    val argPairs = chainCalls.flatMap { c ->
                        c.valueArguments.mapNotNull { it.getArgumentExpression() }
                            .filter { it != da.sqlArg && !isNonValueArg(it) }
                            .map { it to ctx.taint.taintOf(it, visit.tainted) }
                    }
                    val argTraces = argPairs.map { it.second }
                    val idArgs = argPairs.filter { it.second != null && it.second!!.first() in idOrigins }
                    var usesId = idArgs.isNotEmpty()
                    // Ключ не по имени id: считается идентификатором, только если это поле производного запроса (findBy/deleteBy<Поле>).
                    if (usesId && idArgs.all { it.second!!.first() in lookupOrigins }) {
                        usesId = idArgs.any { (e, _) ->
                            val key = lookupKeys.firstOrNull { k -> Regex("""\b${Regex.escape(k.name)}\b""").containsMatchIn(e.text) }?.name
                            key != null && da.repositoryMethod != null &&
                                da.repositoryMethod.substringAfter("By", "").replace("_", "").contains(key.replace("_", ""), ignoreCase = true) &&
                                !da.repositoryMethod.contains("Pageable", ignoreCase = true)
                        }
                    }
                    // Поле тела запроса считается идентификатором объекта, только если оно относится к этой таблице
                    // (orderId -> orders); DTO целиком - только для PUT/PATCH/DELETE. Иначе orderId при создании - внешний ключ.
                    if (usesId && idArgs.all { it.second!!.first() in dtoOrigins }) {
                        val fields = dtoIdFields.values.flatten().toSet()
                        usesId = idArgs.any { (e, _) ->
                            val named = fields.filter { f -> Regex("""\b${Regex.escape(f)}\b""").containsMatchIn(e.text) }
                            if (named.isNotEmpty()) named.any { f -> da.ownerTables.any { t -> fieldMatchesTable(f, t.name) } } else writeOnly
                        }
                    }
                    // Фильтр по владельцу защищает, только если хотя бы одно значение пришло не из запроса (из сессии/токена).
                    val ownerFilterTrusted = da.filtersByOwner && argTraces.any { it == null || it.first() in identityOrigins }
                    // Личность пользователя передана в само чтение (findByIdAndOwner(id, principal.name)) — запись выбирается с учётом владельца.
                    if (argTraces.any { it != null && it.first() in identityOrigins }) continue
                    if (!usesId || da.ownerTables.isEmpty() || ownerFilterTrusted || da.echoesOnlyKey) continue
                    if (da.repositoryMethod != null && !da.repositoryMethod.matches(Regex("(?i)(find|get|read|query|delete|remove)(ById|ByIdOrNull|One|ReferenceById|AllById)?.*"))) {
                        // save/update - запись: IDOR только для PUT/PATCH/DELETE (в POST это создание)
                        if (!(writeOnly && da.repositoryMethod.matches(Regex("(?i)(save|update|patch|merge|persist).*")))) continue
                    }
                    candidates += da to visit.callChain
                }
            }
            if (ownerChecked != null) {
                if (candidates.isNotEmpty()) ctx.dismiss(id, ownerChecked!!, "Владелец проверяется в цепочке вызовов эндпоинта ${ep.paths.joinToString()}")
                continue
            }
            for ((da, chain) in candidates) {
                val file = da.ref.file
                val anchor = da.sqlArg ?: da.call
                // GraphQL: единой HTTP-точки нет, основное место — вызов чтения в обработчике (@QueryMapping), репозиторий — в evidence.
                val gqlCall = if (ep in ctx.graphqlEndpoints) chain.firstOrNull { it.path == ep.file.path } else null
                val (line, endLine) = if (gqlCall != null) gqlCall.line to null else range(file.funLine(da.ref.fn), file.line(anchor))
                val outPath = if (gqlCall != null) gqlCall.path else file.path
                if (!reported.add(outPath to line)) continue
                val table = da.ownerTables.first()
                val neighbour = neighbourOwnerFilter(ctx, table.name, da)
                val evidence = buildList {
                    add(seeds.values.first().first())
                    add(epLoc)
                    addAll(chain)
                    add(da.loc("${if (mutating(ctx, da)) "изменение" else "чтение"} ${table.name} без условия по ${table.ownerColumns.joinToString()}"))
                    add(Location(table.path, table.line, null, "у таблицы ${table.name} есть владелец: ${table.ownerColumns.joinToString()}"))
                    neighbour?.let { add(it) }
                }.distinctBy { it.path to it.line }
                ctx.findings += SastFinding(
                    sastClass = SastClass.OBJECT_AUTHORIZATION, rule = id, severity = Severity.HIGH,
                    path = outPath, line = line, endLine = endLine,
                    title = if (mutating(ctx, da)) "Изменение чужого объекта по идентификатору (IDOR)" else "Чтение чужого объекта по идентификатору (IDOR)",
                    description = "Эндпоинт ${ep.paths.joinToString()} ${if (mutating(ctx, da)) "изменяет/удаляет" else "читает"} запись ${table.name} по идентификатору из запроса, " +
                        "но не проверяет, что она принадлежит текущему пользователю (нет условия по ${table.ownerColumns.joinToString()})." +
                        (if (neighbour != null) " Соседний запрос к той же таблице фильтрует по владельцу — здесь фильтр пропущен." else "") +
                        " Любой вошедший пользователь может прочитать чужие записи, перебирая идентификаторы.",
                    remediation = "Получать пользователя из Principal/@AuthenticationPrincipal и выбирать запись по идентификатору И владельцу " +
                        "(WHERE … AND ${table.ownerColumns.first()} = ?). Чужая и отсутствующая запись должны давать одинаковый ответ (404).",
                    evidence = evidence,
                    fragment = normalizedFragment(da.call),
                )
            }
        }
    }

    private fun mutating(ctx: RuleContext, da: DataAccess): Boolean =
        da.sqlArg?.let { Regex("""(?i)^\s*(update|delete|insert)\b""").containsMatchIn(ru.codeguard.sast.taint.sqlSkeleton(ctx.index, it)) }
            ?: (da.repositoryMethod?.matches(Regex("(?i)(delete|remove|save|update|patch|merge|persist).*")) == true)

    /** Поля DTO (из конструктора и тела класса), похожие на идентификатор объекта; поля-владельцы не считаются. */
    private fun dtoIdFields(ctx: RuleContext, type: String): List<String> {
        val cls = ctx.index.classes[type]?.first as? org.jetbrains.kotlin.psi.KtClass ?: return emptyList()
        val names = cls.primaryConstructorParameters.filter { it.hasValOrVar() }.mapNotNull { it.name } +
            cls.declarations.filterIsInstance<org.jetbrains.kotlin.psi.KtProperty>().mapNotNull { it.name }
        return names.filter { strictIdName.containsMatchIn(it) && !ru.codeguard.sast.spring.isOwnerColumn(it) }
    }

    /** orderId <-> orders / customer_orders; "id" подходит любой таблице. */
    private fun fieldMatchesTable(field: String, table: String): Boolean {
        val stem = ru.codeguard.sast.spring.camelToSnake(field).removeSuffix("_id").removeSuffix("_uuid").replace("_", "")
        if (stem.isEmpty() || stem == "id" || stem == "uuid") return true
        val t = table.replace("_", "").lowercase()
        return t.contains(stem) || stem.contains(t.removeSuffix("s"))
    }

    /** Аргумент — не значение запроса: маппер строк, ссылка на функцию, литерал класса (String::class.java), строковый ключ. */
    private fun isNonValueArg(e: org.jetbrains.kotlin.psi.KtExpression): Boolean =
        e is org.jetbrains.kotlin.psi.KtLambdaExpression || e is org.jetbrains.kotlin.psi.KtCallableReferenceExpression ||
            e is org.jetbrains.kotlin.psi.KtClassLiteralExpression || e.text.contains("::class") ||
            e is org.jetbrains.kotlin.psi.KtStringTemplateExpression && e.entries.all { it is org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry }

    private val logCall = Regex("""(?i)^(println|print|info|debug|warn|error|trace|log)$""")

    /** Ссылка на личность стоит только внутри журналирования (println, log.info…) — это не проверка владельца. */
    private fun onlyInLogging(ref: KtNameReferenceExpression): Boolean {
        val call = PsiTreeUtil.getParentOfType(ref, KtCallExpression::class.java) ?: return false
        return call.calleeName?.let { logCall.matches(it) } == true
    }

    /** Личность из SecurityContextHolder в теле эндпоинта: владелец, вероятно, проверяется там же. */
    private fun identityUse(ep: Endpoint): String? {
        val body = ep.fn.bodyExpression ?: return null
        if (body.text.contains("SecurityContextHolder")) return "Эндпоинт читает пользователя из SecurityContextHolder"
        return null
    }

    /** Явное сравнение значения, пришедшего от личности (principal.name, user.id и производные), с другим значением: ==, !=, equals. */
    private fun identityComparison(text: String, tainted: Map<String, Trace>, origins: Set<Location>): String? {
        for ((name, trace) in tainted) {
            if (trace.firstOrNull() !in origins) continue
            val n = Regex.escape(name)
            val cmp = Regex("""\b$n\b[\w.?!()]*\s*[!=]=(?!=?\s*null\b)|[!=]=\s*(?!null\b)[\w.?!()]*\b$n\b|\.equals\(\s*$n\b|\b$n\b[\w.?!]*\.equals\(""")
            if (cmp.containsMatchIn(text)) return name
        }
        return null
    }

    /** Маршрут публичный, закрыт или только для сотрудников — это не IDOR (публичный — забота route-authorization). */
    private fun accessExclusion(ctx: RuleContext, ep: Endpoint): String? {
        if (ctx.securityChains.isEmpty()) return null
        for (path in ep.paths) for (m in ep.methods.ifEmpty { setOf<String?>(null) }) {
            ctx.securityChains.flatten().firstOrNull { it.access == Access.IGNORED && it.patterns.any { p -> ru.codeguard.sast.spring.antMatch(p, path) } }
                ?.let { return "Маршрут исключён из Spring Security (${it.accessText}) — оценивается правилом route-authorization" }
            val rule = ctx.securityChains.firstNotNullOfOrNull { effectiveRule(it, m, path) } ?: continue
            return when (rule.access) {
                Access.PERMIT_ALL, Access.IGNORED -> "Маршрут публичный (${rule.accessText}) — оценивается правилом route-authorization"
                Access.DENY_ALL -> "Маршрут закрыт (${rule.accessText})"
                Access.ROLE -> {
                    // Только для сотрудников, если ВСЕ роли служебные: hasAnyRole("CLIENT", "MANAGER") клиенту доступен.
                    val roles = Regex("\"([^\"]+)\"").findAll(rule.accessText).map { it.groupValues[1] }.toList()
                    if (roles.isNotEmpty() && roles.all { staffRole.containsMatchIn(it) }) "Маршрут только для сотрудников (${rule.accessText}) — доступ ко всем записям по замыслу" else null
                }
                Access.AUTHENTICATED -> null
            }
        }
        return null
    }

    /** Другой запрос к той же таблице, который фильтрует по владельцу, — подтверждает, что ограничение задумано. */
    private fun neighbourOwnerFilter(ctx: RuleContext, table: String, self: DataAccess): Location? =
        ctx.index.functions.asSequence().flatMap { dataAccessesIn(ctx, it).asSequence() }
            .firstOrNull { it.call != self.call && it.filtersByOwner && it.tables.any { t -> t.name == table } }
            ?.loc("соседний запрос к $table фильтрует по владельцу")
}
