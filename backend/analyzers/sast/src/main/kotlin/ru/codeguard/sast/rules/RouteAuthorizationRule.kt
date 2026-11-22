package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtClass
import ru.codeguard.sast.index.normalizedFragment
import ru.codeguard.sast.model.Location
import ru.codeguard.sast.model.SastClass
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Severity
import ru.codeguard.sast.spring.Access
import ru.codeguard.sast.spring.Endpoint
import ru.codeguard.sast.spring.SecurityRule
import ru.codeguard.sast.spring.antMatch
import ru.codeguard.sast.spring.effectiveRule
import ru.codeguard.sast.spring.patternsOverlap

/**
 * route-authorization: маршрут открыт шире, чем задумано правилами безопасности.
 *
 * Spring Security применяет первое совпавшее правило, поэтому:
 *  1. Затенение: permitAll (или authenticated / web.ignoring) на путь, который ниже покрывает более строгое правило
 *     (hasRole, authenticated) — строгое правило для этого пути никогда не сработает.
 *     Типичный безопасный случай «/auth/(всё) permitAll, затем /(всё) authenticated» отсекаем по смыслу пути (публичные слова)
 *     и по содержимому маршрута: дыра — когда маршрут отдаёт данные из таблиц с владельцем или путь служебный.
 *  2. Публичный маршрут к персональным данным: permitAll на эндпоинт, который читает owner-колонки (customer_id, user_id…).
 * anyRequest() не считается «более строгим правилом ниже» — это общий запрет по умолчанию.
 */
class RouteAuthorizationRule : SastRule {
    override val id = "sast.route.public-sensitive-route"

    private val publicWords = Regex("""(?i)(^|/)(auth|login|logout|register|signup|sign-up|token|refresh|public|health|info|docs?|swagger[^/]*|openapi|v3|api-docs|static|assets|css|js|images?|img|favicon[^/]*|webjars|error|catalog|ping|status|version)(/|$)""")
    private val sensitiveWords = Regex("""(?i)(^|/)(admin|internal|export|exports|private|manage|management|report|reports|download|backup|dump|users?|customers?|accounts?|billing|payments?|orders?|tickets?|audit|actuator|ops|operations)(/|$|\*)""")

    /** Служебные области: открывать их без входа — ошибка конфигурации даже без затенения. */
    private val adminWords = Regex("""(?i)(^|/)(admin|internal|actuator|management|manage|private|ops|operations)(/|$|\*)""")
    /** Безопасные точки actuator, которые принято открывать. */
    private val actuatorSafe = Regex("""(?i)/actuator/(health|info)(/\*\*)?/?$""")

    override fun check(ctx: RuleContext) {
        checkSecurityRules(ctx)
        checkMethodLevel(ctx)
    }



    private fun checkSecurityRules(ctx: RuleContext) {
        val reported = mutableSetOf<SecurityRule>()
        val allRules = ctx.securityChains.flatten()
        var pairs = 0
        var limitReported = false
        for (chain in ctx.securityChains) {
            chain.forEachIndexed { i, rule ->
                if (rule.access !in setOf(Access.PERMIT_ALL, Access.AUTHENTICATED, Access.IGNORED)) return@forEachIndexed
                // anyRequest(): дыра, только если общий «по умолчанию открыто» реально отдаёт данные владельцев.
                if (rule.anyRequest && rule.access != Access.PERMIT_ALL) return@forEachIndexed
                // Preflight CORS (OPTIONS /**) обязан быть открыт — это не дыра.
                if (rule.method == "OPTIONS") {
                    ctx.dismiss(id, rule.file.loc(rule.element), "permitAll для OPTIONS — preflight-запросы CORS, данных не отдают")
                    return@forEachIndexed
                }
                val later = if (rule.access == Access.IGNORED) allRules.filter { it.access != Access.IGNORED } else chain.drop(i + 1)
                val shadowed = later.filter { s ->
                    if (!s.anyRequest && s.access.level > rule.access.level) {
                        if (pairs >= MAX_RULE_PAIRS) {
                            if (!limitReported) {
                                limitReported = true
                                ctx.unresolved("rule-limit", rule.file.loc(rule.element), "слишком много правил доступа — проверены первые $MAX_RULE_PAIRS пар")
                            }
                            false
                        } else {
                            pairs++
                            methodsOverlap(rule.method, s.method) && rule.patterns.any { p -> s.patterns.any { q -> patternsOverlap(p, q) } }
                        }
                    } else false
                }
                val allGoverned = endpointsGovernedBy(ctx, rule, chain)
                // Эндпоинты под @PreAuthorize/@Secured при включённой защите методов закрыты и без HTTP-правила.
                val (methodSecured, endpoints) = allGoverned.partition { methodSecured(ctx, it) }
                if (allGoverned.isNotEmpty() && endpoints.isEmpty()) {
                    ctx.dismiss(id, rule.file.loc(rule.element), "${rule.accessText} на ${rule.patterns.joinToString().ifEmpty { "anyRequest" }}: эндпоинты защищены на уровне метода (${methodSecured.first().methodSecurity.first()})")
                    return@forEachIndexed
                }
                val exposures = endpoints.flatMap { ep -> ownerDataExposure(ctx, ep).map { ep to it } }
                if (rule.anyRequest) {
                    if (exposures.isNotEmpty()) { reportFallback(ctx, rule, exposures); return@forEachIndexed }
                    // Отдельная цепочка с securityMatcher("/ops/**") и anyRequest().permitAll(): весь служебный контур открыт.
                    val scoped = rule.scope.isNotEmpty() && rule.access == Access.PERMIT_ALL
                    val serviceScope = scoped && rule.scope.any { adminWords.containsMatchIn(it) && !actuatorSafe.containsMatchIn(it) || sensitiveWords.containsMatchIn(it) } &&
                        !rule.scope.all { publicWords.containsMatchIn(it) }
                    if (serviceScope && reported.add(rule)) reportScopedFallback(ctx, rule, endpoints)
                    return@forEachIndexed
                }
                val path = rule.patterns.joinToString(", ")
                val benign = rule.patterns.all { publicWords.containsMatchIn(it) }
                val sensitivePath = rule.patterns.any { sensitiveWords.containsMatchIn(it) }

                val verdict: String? = when {
                    benign && exposures.isEmpty() -> null
                    shadowed.any { it.access == Access.ROLE } && (sensitivePath || exposures.isNotEmpty() || !benign) ->
                        "Правило ${rule.accessText} для $path стоит раньше более строгого ${shadowed.first().accessText} для ${shadowed.first().patterns.joinToString()} и затеняет его: первое совпадение побеждает."
                    shadowed.isNotEmpty() && (sensitivePath || exposures.isNotEmpty()) ->
                        "Правило ${rule.accessText} для $path затеняет более строгое ${shadowed.first().accessText} для ${shadowed.first().patterns.joinToString()}."
                    rule.access == Access.PERMIT_ALL && exposures.isNotEmpty() ->
                        "Маршрут $path открыт без входа (permitAll), но отдаёт данные с владельцем записи."
                    rule.access == Access.PERMIT_ALL && rule.patterns.any { adminWords.containsMatchIn(it) && !actuatorSafe.containsMatchIn(it) } ->
                        "Служебный маршрут $path открыт без входа (permitAll)."
                    rule.access == Access.AUTHENTICATED && rule.patterns.any { adminWords.containsMatchIn(it) && !actuatorSafe.containsMatchIn(it) } &&
                        !benign && coveredByEarlierRole(rule, chain.take(i)) == false ->
                        "Служебный маршрут $path защищён только ${rule.accessText}: доступ есть у любого вошедшего пользователя, роль (администратор, оператор) не требуется."
                    rule.access == Access.PERMIT_ALL && sensitivePath && !benign ->
                        "Маршрут $path с чувствительными данными (выгрузки, отчёты, пользователи, платежи) открыт без входа (permitAll)."
                    rule.access == Access.IGNORED && (sensitivePath || exposures.isNotEmpty()) ->
                        "Путь $path исключён из Spring Security (web.ignoring) — к нему не применяются никакие правила доступа."
                    else -> null
                }
                if (verdict == null) {
                    if (rule.access != Access.AUTHENTICATED) ctx.dismiss(id, rule.file.loc(rule.element), "${rule.accessText} на $path: более строгих правил для этого пути нет, персональные данные маршрут не отдаёт")
                    return@forEachIndexed
                }
                if (!reported.add(rule)) return@forEachIndexed
                val (line, endLine) = range(rule.file.line(rule.element), rule.file.endLine(rule.element))
                val evidence = mutableListOf(rule.file.loc(rule.element, "${rule.accessText} ${rule.method ?: ""} $path".replace("  ", " ")))
                shadowed.take(2).forEach { evidence += it.file.loc(it.element, "затенённое правило ${it.accessText} ${it.patterns.joinToString()}") }
                endpoints.take(2).forEach { evidence += it.file.loc(it.fn.nameIdentifier ?: it.fn, "эндпоинт ${it.methods.joinToString("|").ifEmpty { "ANY" }} ${it.paths.joinToString()}") }
                exposures.take(2).forEach { (_, loc) -> evidence += loc }
                ctx.findings += SastFinding(
                    sastClass = SastClass.ROUTE_AUTHORIZATION, rule = id, severity = Severity.HIGH,
                    path = rule.file.path, line = line, endLine = endLine,
                    title = "Маршрут открыт шире, чем задумано",
                    description = verdict + (if (exposures.isNotEmpty()) " Маршрут возвращает данные клиентов." else "") +
                        " Любой пользователь (или аноним) получает доступ, который правила безопасности должны были ограничить.",
                    remediation = "Убрать ${rule.accessText} для $path или перенести правило ниже и потребовать нужную роль " +
                        (shadowed.firstOrNull { it.access == Access.ROLE }?.accessText ?: "(hasRole(...))") +
                        "; проверить доступ гостя, клиента и сотрудника тестом.",
                    evidence = evidence.distinctBy { it.path to it.line },
                    fragment = normalizedFragment(rule.element),
                )
            }
        }
    }

    /** Все шаблоны правила пересекаются с более ранним правилом с ролью — оно и действует. */
    private fun coveredByEarlierRole(rule: SecurityRule, earlier: List<SecurityRule>): Boolean =
        rule.patterns.all { p -> earlier.any { e -> e.access == Access.ROLE && !e.anyRequest && e.patterns.any { q -> patternsOverlap(p, q) } } }

    private val roleCheck = Regex("""(?i)has(Any)?(Role|Authority)\b|@Secured|@RolesAllowed""")
    private val methodAccessAnnotations = setOf("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll")

    /** Аннотации доступа на методе и классе контроллера. */
    private fun accessAnnotations(ep: Endpoint): List<KtAnnotationEntry> {
        val cls = PsiTreeUtil.getParentOfType(ep.fn, KtClass::class.java)
        return (ep.fn.annotationEntries + (cls?.annotationEntries ?: emptyList())).filter { it.shortName?.asString() in methodAccessAnnotations }
    }

    private fun opensToAll(ctx: RuleContext, a: KtAnnotationEntry): Boolean =
        a.shortName?.asString() == "PermitAll" ||
            (a.shortName?.asString() == "PreAuthorize" &&
                ctx.index.stringValue(a.valueArguments.firstOrNull()?.getArgumentExpression())?.trim()?.removeSuffix("()").equals("permitAll", true))

    private fun effectiveFor(ctx: RuleContext, ep: Endpoint): SecurityRule? {
        for (path in ep.paths) for (m in ep.methods.ifEmpty { setOf<String?>(null) }) {
            ctx.securityChains.firstNotNullOfOrNull { effectiveRule(it, m, path) }?.let { return it }
        }
        return null
    }

    private fun sensitiveEndpoint(ep: Endpoint): Boolean =
        ep.paths.any { sensitiveWords.containsMatchIn(it) } && !ep.paths.all { publicWords.containsMatchIn(it) }

    /** Защита на уровне методов: @PreAuthorize("permitAll()") / @PermitAll на чувствительных маршрутах и метод без проверки среди методов с ролями. */
    private fun checkMethodLevel(ctx: RuleContext) {
        val methodSecurityOn = ctx.index.project.kotlin.any { f -> f.psi.text.contains(Regex("""@Enable(Global)?MethodSecurity""")) }
        val reportedFns = mutableSetOf<Endpoint>()
        // permitAll на методе чувствительного маршрута
        for (ep in ctx.endpoints) {
            val open = accessAnnotations(ep).firstOrNull { opensToAll(ctx, it) } ?: continue
            if (!sensitiveEndpoint(ep)) continue
            val rule = effectiveFor(ctx, ep)
            if (rule != null && rule.access != Access.AUTHENTICATED) continue
            if (!reportedFns.add(ep)) continue
            reportEndpoint(ctx, ep, open, "Чувствительный маршрут ${ep.paths.joinToString()} помечен ${open.text} — проверка доступа на методе отключена явно" +
                (if (rule == null) " и HTTP-правила для него нет." else ", а HTTP-правило требует лишь входа."))
        }
        // один метод без проверки среди методов с ролями
        if (!methodSecurityOn) return
        val byClass = ctx.endpoints.groupBy { PsiTreeUtil.getParentOfType(it.fn, KtClass::class.java) }
        for ((cls, eps) in byClass) {
            if (cls == null || eps.size < 3) continue
            val unsecured = eps.filter { accessAnnotations(it).isEmpty() }
            val secured = eps - unsecured.toSet()
            if (secured.size < 2 || unsecured.isEmpty() || unsecured.size >= secured.size) continue
            if (secured.any { ep -> accessAnnotations(ep).none { roleCheck.containsMatchIn(it.text) } }) continue
            for (ep in unsecured) {
                if (ep.paths.all { publicWords.containsMatchIn(it) }) continue
                val rule = effectiveFor(ctx, ep)
                if (rule != null && rule.access != Access.AUTHENTICATED) continue
                if (!reportedFns.add(ep)) continue
                reportEndpoint(ctx, ep, accessAnnotations(secured.first()).first(),
                    "Метод ${ep.paths.joinToString()} без проверки доступа, хотя остальные методы контроллера ${cls.name} требуют роль (@PreAuthorize/@Secured), а защита методов включена. " +
                        "Любой вошедший пользователь (или аноним) вызовет его без нужной роли.")
            }
        }
    }

    private fun reportEndpoint(ctx: RuleContext, ep: Endpoint, related: PsiElement, text: String) {
        val anchor = ep.fn.nameIdentifier ?: ep.fn
        ctx.findings += SastFinding(
            sastClass = SastClass.ROUTE_AUTHORIZATION, rule = id, severity = Severity.HIGH,
            path = ep.file.path, line = ep.file.funLine(ep.fn), endLine = null,
            title = "Маршрут открыт шире, чем задумано",
            description = text,
            remediation = "Добавить @PreAuthorize(\"hasRole('…')\") на метод (как у соседних методов) или убрать permitAll; проверить доступ ролью и без входа тестом.",
            evidence = listOf(ep.file.loc(anchor, "эндпоинт ${ep.methods.joinToString("|").ifEmpty { "ANY" }} ${ep.paths.joinToString()}"), ep.file.loc(related, "аннотация доступа")).distinctBy { it.path to it.line },
            fragment = normalizedFragment(anchor),
        )
    }

    private fun methodsOverlap(a: String?, b: String?) = a == null || b == null || a == b

    /** Метод закрыт аннотацией доступа, и защита методов в проекте включена. */
    private fun methodSecured(ctx: RuleContext, ep: Endpoint): Boolean {
        if (ep.methodSecurity.none { Regex("""(?i)has(Any)?(Role|Authority)|isAuthenticated|isFullyAuthenticated|@Secured|@RolesAllowed|principal|authentication""").containsMatchIn(it) }) return false
        return ctx.index.project.kotlin.any { f -> f.psi.text.contains(Regex("""@Enable(Global)?MethodSecurity""")) }
    }

    /** securityMatcher("/ops/...") + anyRequest().permitAll(): служебный контур открыт целиком. */
    private fun reportScopedFallback(ctx: RuleContext, rule: SecurityRule, endpoints: List<Endpoint>) {
        val (line, endLine) = range(rule.file.line(rule.element), rule.file.endLine(rule.element))
        val scope = rule.scope.joinToString()
        ctx.findings += SastFinding(
            sastClass = SastClass.ROUTE_AUTHORIZATION, rule = id, severity = Severity.HIGH,
            path = rule.file.path, line = line, endLine = endLine,
            title = "Служебные маршруты открыты без входа",
            description = "Цепочка безопасности для $scope заканчивается правилом anyRequest().${rule.accessText}: все маршруты этого контура доступны без входа" +
                (if (endpoints.isNotEmpty()) ", в том числе ${endpoints.flatMap { it.paths }.distinct().take(3).joinToString()}." else "."),
            remediation = "Заменить anyRequest().permitAll() для $scope на authenticated() / hasRole(...) и открыть явно только публичные маршруты.",
            evidence = (listOf(rule.file.loc(rule.element, "anyRequest().${rule.accessText} в цепочке $scope")) +
                endpoints.take(2).map { it.file.loc(it.fn.nameIdentifier ?: it.fn, "эндпоинт ${it.paths.joinToString()}") }).distinctBy { it.path to it.line },
            fragment = normalizedFragment(rule.element),
        )
    }

    /** anyRequest().permitAll(): всё, что не перечислено выше, открыто — и среди этого есть данные владельцев. */
    private fun reportFallback(ctx: RuleContext, rule: SecurityRule, pairs: List<Pair<Endpoint, Location>>) {
        val exposed = pairs.map { it.first }.distinct().take(3)
        val exposures = pairs.map { it.second }
        val (line, endLine) = range(rule.file.line(rule.element), rule.file.endLine(rule.element))
        ctx.findings += SastFinding(
            sastClass = SastClass.ROUTE_AUTHORIZATION, rule = id, severity = Severity.HIGH,
            path = rule.file.path, line = line, endLine = endLine,
            title = "Маршруты открыты по умолчанию",
            description = "Правило по умолчанию anyRequest().${rule.accessText} открывает без входа все маршруты, не перечисленные выше, " +
                "в том числе ${exposed.flatMap { it.paths }.joinToString()}, которые отдают данные с владельцем записи.",
            remediation = "Заменить anyRequest().permitAll() на anyRequest().authenticated() (или denyAll()) и открыть явно только публичные маршруты.",
            evidence = (listOf(rule.file.loc(rule.element, "anyRequest().${rule.accessText}")) +
                exposed.map { it.file.loc(it.fn.nameIdentifier ?: it.fn, "эндпоинт ${it.paths.joinToString()}") } + exposures.take(2)).distinctBy { it.path to it.line },
            fragment = normalizedFragment(rule.element),
        )
    }

    /** Эндпоинты, для которых это правило — первое совпавшее (или все совпавшие для web.ignoring). */
    private fun endpointsGovernedBy(ctx: RuleContext, rule: SecurityRule, chain: List<SecurityRule>): List<Endpoint> =
        ctx.endpoints.filter { ep ->
            ep.paths.any { path ->
                if (rule.access == Access.IGNORED) rule.patterns.any { antMatch(it, path) }
                else (ep.methods.ifEmpty { setOf<String?>(null) }).any { m -> effectiveRule(chain, m, path) === rule }
            }
        }

    /** Места, где эндпоинт (или вызываемые им функции) читает данные таблиц с owner-колонками. */
    private fun ownerDataExposure(ctx: RuleContext, ep: Endpoint): List<Location> =
        reachable(ctx, ctx.ref(ep)).flatMap { (ref, _) ->
            dataAccessesIn(ctx, ref).filter { it.exposesOwnerData }.map { da ->
                da.loc("читает ${da.ownerTables.joinToString { t -> "${t.name}(${t.ownerColumns.joinToString()})" }}")
            }
        }
}

private const val MAX_RULE_PAIRS = 5000
