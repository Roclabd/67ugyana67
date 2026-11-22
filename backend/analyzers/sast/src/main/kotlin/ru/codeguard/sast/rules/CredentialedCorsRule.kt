package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtProperty
import ru.codeguard.sast.index.args
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.index.normalizedFragment
import ru.codeguard.sast.index.receiver
import ru.codeguard.sast.index.strings
import ru.codeguard.sast.index.stringList
import ru.codeguard.sast.model.SastClass
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Severity
import ru.codeguard.sast.project.KotlinSource
import ru.codeguard.sast.spring.lambda
import ru.codeguard.sast.spring.topOfChain

/**
 * credentialed-cors: в одной CORS-конфигурации одновременно «любой origin» и разрешённые credentials.
 * Конфигурация — это один объект CorsConfiguration (apply-блок или переменная), одна цепочка
 * registry.addMapping(…).allowedOrigins(…).allowCredentials(…), одна аннотация @CrossOrigin
 * или один обработчик, отражающий заголовок Origin вместе с Access-Control-Allow-Credentials: true.
 */
class CredentialedCorsRule : SastRule {
    override val id = "sast.cors.any-origin-with-credentials"

    private val originProps = setOf("allowedOrigins", "allowedOriginPatterns")
    private val originSetters = setOf("setAllowedOrigins", "setAllowedOriginPatterns", "addAllowedOrigin", "addAllowedOriginPattern", "allowedOrigins", "allowedOriginPatterns")

    /** Найденная пара: «любой origin» и credentials в одной конфигурации. */
    private class Hit(val origin: PsiElement, val credentials: PsiElement, val kind: String)

    override fun check(ctx: RuleContext) {
        for (file in ctx.index.project.kotlin) {
            val hits = mutableListOf<Hit>()
            // 1. CorsConfiguration().apply { … }
            PsiTreeUtil.findChildrenOfType(file.psi, KtCallExpression::class.java)
                .filter { it.calleeName == "CorsConfiguration" }
                .forEach { ctor ->
                    val applyCall = ((ctor.parent as? KtDotQualifiedExpression)?.selectorExpression as? KtCallExpression)?.takeIf { it.calleeName in setOf("apply", "also") }
                    val scope = applyCall?.lambda()
                    if (scope != null) scan(ctx, scope, null)?.let { hits += it }
                    // val c = CorsConfiguration(); c.allowCredentials = true …
                    val prop = PsiTreeUtil.getParentOfType(ctor, KtProperty::class.java)
                    val fn = PsiTreeUtil.getParentOfType(ctor, KtNamedFunction::class.java)
                    // val c = CorsConfiguration().applyPermitDefaultValues() — «любой origin» уже в инициализаторе
                    val permitDefaults = PsiTreeUtil.findChildrenOfType(prop?.initializer ?: ctor, KtCallExpression::class.java)
                        .firstOrNull { it.calleeName == "applyPermitDefaultValues" }
                    if (prop?.name != null && fn != null && prop.isLocal) scan(ctx, fn, prop.name, permitDefaults)?.let { hits += it }
                }
            // 1б. Объект конфигурации из фабрики или с объявленным типом: val c = defaults(); val c: CorsConfiguration = …
            PsiTreeUtil.findChildrenOfType(file.psi, KtProperty::class.java)
                .filter { it.isLocal && it.name != null && it.initializer?.text?.startsWith("CorsConfiguration(") != true && isCorsConfiguration(ctx, it) }
                .forEach { prop ->
                    val fn = PsiTreeUtil.getParentOfType(prop, KtNamedFunction::class.java) ?: return@forEach
                    scan(ctx, fn, prop.name)?.let { hits += it }
                }
            // 2. Цепочка CorsRegistry: addMapping(…).allowedOrigins("*")….allowCredentials(true)
            PsiTreeUtil.findChildrenOfType(file.psi, KtCallExpression::class.java)
                .filter { it.calleeName == "allowCredentials" && isTrueArg(it) && it.receiver != null }
                .forEach { cred ->
                    val chain = topOfChain(cred)
                    val candidates = PsiTreeUtil.findChildrenOfType(chain, KtCallExpression::class.java).toMutableList()
                    // val reg = registry.addMapping("/**"); reg.allowedOrigins("*"); reg.allowCredentials(true)
                    val head = leftmostReceiver(chain)
                    val fn = PsiTreeUtil.getParentOfType(cred, KtNamedFunction::class.java)
                    if (head != null && fn != null) {
                        candidates += PsiTreeUtil.findChildrenOfType(fn, KtCallExpression::class.java)
                            .filter { leftmostReceiver(topOfChain(it)) == head }
                    }
                    val origin = candidates.firstOrNull { it.calleeName in setOf("allowedOrigins", "allowedOriginPatterns") && it.valueArguments.any { a -> containsWildcard(ctx, a.getArgumentExpression(), it.calleeName == "allowedOriginPatterns") } }
                    if (origin != null) hits += Hit(origin, cred, "CorsRegistry")
                }
            // 3. @CrossOrigin(origins = ["*"], allowCredentials = "true")
            PsiTreeUtil.findChildrenOfType(file.psi, KtAnnotationEntry::class.java)
                .filter { it.shortName?.asString() == "CrossOrigin" }
                .forEach { ann ->
                    val a = ann.args()
                    val credentials = a["allowCredentials"]?.let { ctx.index.stringValue(it) == "true" } == true
                    val origins = ctx.index.strings(a["origins"] ?: a["value"])
                    val patterns = ctx.index.strings(a["originPatterns"])
                    if (credentials && ((origins.isEmpty() && patterns.isEmpty()) || "*" in origins || patterns.any { anyHostPattern(it) })) hits += Hit(ann, ann, "@CrossOrigin")
                }
            // 4. Отражение Origin вручную: setHeader("Access-Control-Allow-Origin", request.getHeader("Origin")) + credentials
            PsiTreeUtil.findChildrenOfType(file.psi, KtNamedFunction::class.java).forEach { fn ->
                val headerCalls = PsiTreeUtil.findChildrenOfType(fn, KtCallExpression::class.java).filter { it.calleeName in setOf("setHeader", "addHeader", "header", "set", "add") }
                val reflect = headerCalls.firstOrNull { c ->
                    isHeaderName(ctx, c.valueArguments.getOrNull(0)?.getArgumentExpression(), "Access-Control-Allow-Origin", "ACCESS_CONTROL_ALLOW_ORIGIN") &&
                        (readsOrigin(c.valueArguments.getOrNull(1)?.getArgumentExpression(), fn) ||
                            ctx.index.stringValue(c.valueArguments.getOrNull(1)?.getArgumentExpression()) == "*")
                }
                val cred = headerCalls.firstOrNull { c ->
                    isHeaderName(ctx, c.valueArguments.getOrNull(0)?.getArgumentExpression(), "Access-Control-Allow-Credentials", "ACCESS_CONTROL_ALLOW_CREDENTIALS") &&
                        c.valueArguments.getOrNull(1)?.getArgumentExpression()?.let { v -> ctx.index.stringValue(v) == "true" || v.text == "true" || v.text == "true.toString()" } == true
                }
                if (reflect != null && cred != null) hits += Hit(reflect, cred, "заголовки ответа")
            }

            hits.distinctBy { file.line(it.origin) }.forEach { report(ctx, file, it) }
        }
    }

    /** Ищет в области [scope] (apply-блок или функция) пару «любой origin» + credentials; [receiver] — имя переменной конфигурации. */
    /**
     * Ищет в области [scope] (apply-блок или функция) пару «любой origin» + credentials; [receiver] — имя переменной конфигурации.
     * Учитывается ПОСЛЕДНЕЕ значение: allowedOrigins = listOf("*") с последующей заменой на доверенный origin — не находка.
     */
    private fun scan(ctx: RuleContext, scope: PsiElement, receiver: String?, initialOrigin: PsiElement? = null): Hit? {
        var origin: PsiElement? = initialOrigin
        var credentials: PsiElement? = null
        val assigns = PsiTreeUtil.findChildrenOfType(scope, KtBinaryExpression::class.java).filter { it.operationToken == KtTokens.EQ }
        val calls = PsiTreeUtil.findChildrenOfType(scope, KtCallExpression::class.java)
        // События в порядке текста: присваивания свойств и вызовы сеттеров одного объекта конфигурации.
        val events = (assigns + calls).sortedBy { it.textRange.startOffset }
        for (e in events) {
            if (e is KtBinaryExpression) {
                val (recv, prop) = target(e.left) ?: continue
                if (receiver != null && recv != receiver) continue
                if (receiver == null && recv != null && recv != "this" && recv != "it") continue
                when (prop) {
                    in originProps -> origin = if (containsWildcard(ctx, e.right, prop == "allowedOriginPatterns") || reflectsOrigin(e.right)) e else null
                    "allowCredentials" -> credentials = if (e.right?.text == "true") e else null
                }
            } else if (e is KtCallExpression) {
                val recv = (e.receiver as? KtNameReferenceExpression)?.getReferencedName()
                if (receiver != null && recv != receiver) continue
                if (receiver == null && e.receiver != null && e.receiver?.text !in setOf("this", "it")) continue
                when (e.calleeName) {
                    in setOf("setAllowedOrigins", "setAllowedOriginPatterns") ->
                        origin = if (e.valueArguments.any { containsWildcard(ctx, it.getArgumentExpression(), e.calleeName == "setAllowedOriginPatterns") }) e else null
                    in setOf("addAllowedOrigin", "addAllowedOriginPattern") ->
                        if (e.valueArguments.any { containsWildcard(ctx, it.getArgumentExpression(), e.calleeName == "addAllowedOriginPattern") }) origin = e
                    // applyPermitDefaultValues() разрешает все origin, если они не заданы явно
                    "applyPermitDefaultValues" -> origin = origin ?: e
                    "setAllowCredentials" -> credentials = if (isTrueArg(e)) e else null
                }
            }
        }
        return if (origin != null && credentials != null) Hit(origin, credentials, "CorsConfiguration") else null
    }

    /** Локальная переменная — объект CorsConfiguration: объявленный тип или функция проекта, возвращающая его. */
    private fun isCorsConfiguration(ctx: RuleContext, p: KtProperty): Boolean {
        if (p.typeReference?.text?.endsWith("CorsConfiguration") == true) return true
        val call = p.initializer as? KtCallExpression ?: return false
        return ctx.index.functions.any { it.name == call.calleeName && it.fn.typeReference?.text?.endsWith("CorsConfiguration") == true }
    }

    private fun target(left: KtExpression?): Pair<String?, String>? {
        return when (left) {
            is KtNameReferenceExpression -> null to left.getReferencedName()
            is KtDotQualifiedExpression -> left.receiverExpression.text to ((left.selectorExpression as? KtNameReferenceExpression)?.getReferencedName() ?: return null)
            else -> null
        }
    }

    /** Имя локальной переменной в начале цепочки reg.a().b(): «reg»; null, если начало — не простое имя. */
    private fun leftmostReceiver(e: org.jetbrains.kotlin.com.intellij.psi.PsiElement): String? {
        var cur = e
        while (cur is KtDotQualifiedExpression) cur = cur.receiverExpression
        val name = (cur as? KtNameReferenceExpression)?.getReferencedName() ?: return null
        val fn = PsiTreeUtil.getParentOfType(e, KtNamedFunction::class.java) ?: return null
        val isLocal = PsiTreeUtil.findChildrenOfType(fn, KtProperty::class.java).any { it.isLocal && it.name == name }
        return if (isLocal) name else null
    }

    private fun isTrueArg(call: KtCallExpression) = call.valueArguments.firstOrNull()?.getArgumentExpression()?.text == "true"

    /**
     * Шаблон origin допускает любой хост: звёздочка, схема со звёздочкой (в т. ч. с портом); шаблон поддоменов своего домена ограничен.
     * Для шаблонов (allowedOriginPatterns) схема со звёздочкой тоже "любой origin"; для allowedOrigins - только "*".
     */
    private val fullWildcard = Regex("""^([a-zA-Z][a-zA-Z0-9+.-]*://)?\*(:(\d+|\*))?$""")
    private val localHost = Regex("""^([a-zA-Z][a-zA-Z0-9+.-]*://)?(localhost|127\.0\.0\.1|\[::1])(:.*)?$""", RegexOption.IGNORE_CASE)

    /** Шаблон origin с подстановкой: любой хост или любой поддомен (схема + «*.» + домен); порт localhost:* не считается. */
    private fun anyHostPattern(s: String): Boolean {
        val t = s.trim()
        return fullWildcard.matches(t) || ('*' in t && !localHost.matches(t))
    }

    private fun isWildcard(ctx: RuleContext, e: KtExpression?, pattern: Boolean = false): Boolean {
        val s = ctx.index.stringValue(e)
        return s == "*" || (pattern && s != null && anyHostPattern(s)) || e?.text?.endsWith("CorsConfiguration.ALL") == true || e?.text == "ALL"
    }

    /** listOf("*"), arrayOf("*"), mutableListOf("*"), "*" , CorsConfiguration.ALL */
    private fun containsWildcard(ctx: RuleContext, e: KtExpression?, pattern: Boolean = false): Boolean {
        if (e == null) return false
        if (isWildcard(ctx, e, pattern)) return true
        // Origins в локальной val/константе/списке: val origins = listOf("*"); allowedOriginPatterns(origins)
        ctx.index.stringList(e)?.let { list -> if (list.any { it == "*" || (pattern && anyHostPattern(it)) }) return true }
        val call = e as? KtCallExpression ?: (e as? KtDotQualifiedExpression)?.selectorExpression as? KtCallExpression ?: return false
        return call.valueArguments.any { isWildcard(ctx, it.getArgumentExpression(), pattern) }
    }

    private fun isHeaderName(ctx: RuleContext, e: KtExpression?, literal: String, constant: String): Boolean =
        ctx.index.stringValue(e).equals(literal, true) || e?.text?.substringAfterLast('.') == constant

    private val originRead = Regex("""(?i)getHeader\(\s*(?:"origin"|(?:\w+\.)*ORIGIN)\s*\)|getFirst\(\s*(?:"origin"|(?:\w+\.)*ORIGIN)\s*\)|headers\[\s*(?:"origin"|(?:\w+\.)*ORIGIN)\s*]|\.origin\b""")
    private val originGuard = Regex("""(?i)\b(in|contains|startsWith|endsWith|matches|equals|allow\w*|trust\w*|valid\w*|whitelist\w*|isAllowed\w*)\b|==""")

    /**
     * Значение заголовка - Origin запроса: прямое чтение (getHeader("Origin"), getHeader(HttpHeaders.ORIGIN))
     * или локальная переменная с таким инициализатором, которая нигде не сверяется со списком разрешённых.
     */
    private fun readsOrigin(value: KtExpression?, fn: KtNamedFunction): Boolean {
        if (value == null) return false
        if (originRead.containsMatchIn(value.text)) return true
        val name = (value as? KtNameReferenceExpression)?.getReferencedName() ?: return false
        val prop = PsiTreeUtil.findChildrenOfType(fn, KtProperty::class.java).firstOrNull { it.isLocal && it.name == name } ?: return false
        if (prop.initializer?.text?.let { originRead.containsMatchIn(it) } != true) return false
        // проверка в условии: if (origin in allowed) / allowed.contains(origin) / isAllowed(origin)
        val checked = PsiTreeUtil.findChildrenOfType(fn, org.jetbrains.kotlin.psi.KtIfExpression::class.java).any { i ->
            i.condition?.text?.let { c -> Regex("""\b${Regex.escape(name)}\b""").containsMatchIn(c) && originGuard.containsMatchIn(c) } == true
        } || PsiTreeUtil.findChildrenOfType(fn, org.jetbrains.kotlin.psi.KtWhenExpression::class.java).any { w ->
            Regex("""\b${Regex.escape(name)}\b""").containsMatchIn(w.subjectExpression?.text ?: "")
        }
        return !checked
    }

    private fun reflectsOrigin(e: KtExpression?): Boolean =
        e?.text?.contains(Regex("""(?i)getHeader\(\s*"origin"\s*\)|headers\[\s*"origin"\s*]""")) == true

    private fun report(ctx: RuleContext, file: KotlinSource, hit: Hit) {
        val (line, endLine) = file.rangeOf(hit.origin, hit.credentials)
        ctx.findings += SastFinding(
            sastClass = SastClass.CREDENTIALED_CORS, rule = id, severity = Severity.MEDIUM,
            path = file.path, line = line, endLine = endLine,
            title = "CORS: любой origin вместе с credentials",
            description = if (hit.origin.text.let { it.contains("*.") && !it.contains("\"*\"") })
                "CORS с cookie разрешён для любого поддомена: в шаблоне origin есть подстановка, а передача credentials включена. " +
                    "Любой сайт на таком поддомене (в т. ч. захваченном) сможет читать приватные ответы от имени пользователя."
            else "В одной CORS-конфигурации (${hit.kind}) разрешены запросы с любого origin и передача cookie/авторизации. " +
                "Сторонний сайт сможет читать ответы приватных маршрутов от имени вошедшего пользователя.",
            remediation = "Разрешить только конкретные доверенные origin (allowedOrigins = listOf(\"https://…\")) или отключить allowCredentials для этого маршрута.",
            evidence = listOf(file.loc(hit.origin, "любой origin"), file.loc(hit.credentials, "allowCredentials = true")).distinct(),
            fragment = normalizedFragment(hit.origin) + " | " + normalizedFragment(hit.credentials),
        )
    }
}
