package ru.codeguard.sast.spring

import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtParameter
import org.jetbrains.kotlin.psi.KtProperty
import ru.codeguard.sast.index.ProjectIndex
import ru.codeguard.sast.index.annotation
import ru.codeguard.sast.index.args
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.index.hasAnnotation
import ru.codeguard.sast.index.stringList
import ru.codeguard.sast.index.strings
import ru.codeguard.sast.project.KotlinSource

// ───────────── Эндпоинты ─────────────

enum class ParamSource { REQUEST_PARAM, PATH_VARIABLE, REQUEST_BODY, REQUEST_HEADER, COOKIE, MODEL_ATTRIBUTE, IMPLICIT, IDENTITY, OTHER }

class EndpointParam(val param: KtParameter, val name: String, val source: ParamSource, val type: String?, val headerName: String?)

class Endpoint(
    val fn: KtNamedFunction,
    val file: KotlinSource,
    val methods: Set<String>,          // пусто — любой метод
    val paths: List<String>,           // полные пути с префиксом класса
    val params: List<EndpointParam>,
    val methodSecurity: List<String>,  // тексты @PreAuthorize/@PostAuthorize/@Secured/@RolesAllowed
)

private val MAPPINGS = mapOf(
    "GetMapping" to "GET", "PostMapping" to "POST", "PutMapping" to "PUT",
    "DeleteMapping" to "DELETE", "PatchMapping" to "PATCH", "RequestMapping" to null,
)

/** Типы, через которые Spring передаёт личность пользователя. */
val IDENTITY_TYPES = setOf(
    "Principal", "Authentication", "UsernamePasswordAuthenticationToken", "JwtAuthenticationToken",
    "OAuth2AuthenticationToken", "AbstractAuthenticationToken", "Jwt", "OidcUser", "UserDetails", "OAuth2User",
)
private val INFRA_TYPES = setOf("HttpServletRequest", "HttpServletResponse", "Model", "ModelMap", "BindingResult", "Errors", "HttpSession", "WebRequest", "Pageable", "Sort", "Locale", "ServerWebExchange")

fun extractEndpoints(index: ProjectIndex): List<Endpoint> {
    val out = mutableListOf<Endpoint>()
    for (f in index.project.kotlin) {
        for (cls in PsiTreeUtil.findChildrenOfType(f.psi, KtClass::class.java)) {
            val isController = cls.hasAnnotation("RestController", "Controller")
            val classMapping = cls.annotation("RequestMapping")
            val prefixes = classMapping?.args()?.let { a -> index.strings(a["value"] ?: a["path"]) }?.ifEmpty { listOf("") } ?: listOf("")
            for (fn in cls.declarations.filterIsInstance<KtNamedFunction>()) {
                val ann = fn.annotationEntries.firstOrNull { it.shortName?.asString() in MAPPINGS.keys } ?: continue
                if (!isController && classMapping == null) continue
                val a = ann.args()
                val methodPaths = index.strings(a["value"] ?: a["path"]).ifEmpty { listOf("") }
                val methods = MAPPINGS[ann.shortName!!.asString()]?.let { setOf(it) }
                    ?: (a["method"]?.let { m -> Regex("""\b(GET|POST|PUT|DELETE|PATCH)\b""").findAll(m.text).map { it.value }.toSet() } ?: emptySet())
                val paths = prefixes.flatMap { p -> methodPaths.map { joinPath(p, it) } }
                val security = (fn.annotationEntries + cls.annotationEntries)
                    .filter { it.shortName?.asString() in setOf("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed") }
                    .map { it.text }
                out += Endpoint(fn, f, methods, paths, fn.valueParameters.map { endpointParam(it) }, security)
            }
        }
    }
    return out
}

/**
 * Обработчики сообщений (Kafka, RabbitMQ, JMS, STOMP): данные приходят извне так же, как в HTTP-запросе.
 * Источники для taint-правил (SQL); для правил доступа (маршруты, IDOR) не используются — у них нет HTTP-пути.
 */
fun extractMessageHandlers(index: ProjectIndex): List<Endpoint> {
    val listenerAnnotations = setOf("KafkaListener", "RabbitListener", "JmsListener", "MessageMapping", "SqsListener", "StreamListener", "KafkaHandler", "RabbitHandler")
    return index.functions.filter { ref -> ref.fn.annotationEntries.any { it.shortName?.asString() in listenerAnnotations } }
        .map { ref -> Endpoint(ref.fn, ref.file, emptySet(), emptyList(), ref.fn.valueParameters.map { endpointParam(it) }, emptyList()) }
}

private val GRAPHQL_MAPPINGS = setOf("QueryMapping", "MutationMapping", "SchemaMapping", "SubscriptionMapping", "BatchMapping")

/**
 * GraphQL-обработчики Spring (@QueryMapping/@MutationMapping/@SchemaMapping): единая точка /graphql, аргументы (@Argument) приходят от клиента.
 * Отдельным списком: для правил маршрутов это не HTTP-пути контроллера; для SQL и IDOR — те же источники данных запроса.
 */
fun extractGraphqlEndpoints(index: ProjectIndex): List<Endpoint> =
    index.functions.filter { ref ->
        ref.fn.annotationEntries.any { it.shortName?.asString() in GRAPHQL_MAPPINGS } &&
            (ref.owner as? KtClass)?.let { it.hasAnnotation("Controller", "RestController") } == true
    }.map { ref ->
        Endpoint(ref.fn, ref.file, emptySet(), listOf("/graphql"), ref.fn.valueParameters.map { endpointParam(it) }, ref.fn.annotationEntries
            .filter { it.shortName?.asString() in setOf("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed") }.map { it.text })
    }

private fun endpointParam(p: KtParameter): EndpointParam {
    val type = p.typeReference?.text?.let { ProjectIndex.simpleType(it) }
    val names = p.annotationEntries.mapNotNull { it.shortName?.asString() }
    val header = p.annotation("RequestHeader")?.args()?.let { a -> (a["value"] ?: a["name"])?.text?.trim('"') }
    val source = when {
        "AuthenticationPrincipal" in names || "CurrentSecurityContext" in names -> ParamSource.IDENTITY
        type in IDENTITY_TYPES -> ParamSource.IDENTITY
        "RequestHeader" in names && header.equals("Authorization", ignoreCase = true) -> ParamSource.IDENTITY
        "RequestParam" in names || "Argument" in names -> ParamSource.REQUEST_PARAM
        "PathVariable" in names -> ParamSource.PATH_VARIABLE
        "RequestBody" in names -> ParamSource.REQUEST_BODY
        "RequestHeader" in names -> ParamSource.REQUEST_HEADER
        "CookieValue" in names -> ParamSource.COOKIE
        "ModelAttribute" in names -> ParamSource.MODEL_ATTRIBUTE
        type in INFRA_TYPES -> ParamSource.OTHER
        // Spring привязывает простые параметры без аннотации как request-параметры.
        else -> ParamSource.IMPLICIT
    }
    return EndpointParam(p, p.name ?: "", source, type, header)
}

fun joinPath(prefix: String, path: String): String {
    val joined = ("/" + prefix.trim('/') + "/" + path.trim('/')).replace(Regex("/+"), "/")
    return if (joined.length > 1) joined.trimEnd('/') else joined
}

// ───────────── Правила Spring Security ─────────────

enum class Access(val level: Int) { IGNORED(-1), PERMIT_ALL(0), AUTHENTICATED(1), ROLE(2), DENY_ALL(3) }

class SecurityRule(
    val order: Int,
    val method: String?,          // null — любой
    val patterns: List<String>,   // пусто + anyRequest
    val anyRequest: Boolean,
    val access: Access,
    val accessText: String,
    val element: PsiElement,
    val file: KotlinSource,
) {
    /** securityMatcher(...) цепочки: правила действуют только на эти пути; пусто — на все. */
    var scope: List<String> = emptyList()
}

private val ACCESS_METHODS = mapOf(
    "permitAll" to Access.PERMIT_ALL, "anonymous" to Access.PERMIT_ALL,
    "authenticated" to Access.AUTHENTICATED, "fullyAuthenticated" to Access.AUTHENTICATED, "rememberMe" to Access.AUTHENTICATED,
    "hasRole" to Access.ROLE, "hasAnyRole" to Access.ROLE, "hasAuthority" to Access.ROLE, "hasAnyAuthority" to Access.ROLE,
    "access" to Access.ROLE, "hasIpAddress" to Access.ROLE,
    "denyAll" to Access.DENY_ALL,
)
private val MATCHER_METHODS = setOf("requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers", "securityMatchers")
private val HTTP_METHODS = setOf("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

/**
 * Цепочки authorizeHttpRequests / authorizeRequests в порядке объявления, по каждому файлу конфигурации.
 * Поддержаны формы: rules.requestMatchers(...).permitAll() в лямбде, Java-стиль цепочкой,
 * Kotlin DSL authorize("/x", permitAll), а также web.ignoring().requestMatchers(...).
 */
fun extractSecurityChains(index: ProjectIndex): List<List<SecurityRule>> {
    val chains = mutableListOf<List<SecurityRule>>()
    for (f in index.project.kotlin) {
        val roots = PsiTreeUtil.findChildrenOfType(f.psi, KtCallExpression::class.java)
            .filter { it.calleeName in setOf("authorizeHttpRequests", "authorizeRequests", "authorizeExchange") }
        for (root in roots) {
            val rules = mutableListOf<SecurityRule>()
            // Все вызовы доступа внутри лямбды/цепочки — по порядку в тексте.
            val scope: PsiElement = root.lambda() ?: topOfChain(root)
            val accessCalls = PsiTreeUtil.findChildrenOfType(scope, KtCallExpression::class.java)
                .filter { it.calleeName in ACCESS_METHODS.keys || it.calleeName == "authorize" }
                .sortedBy { it.textRange.startOffset }
            for (call in accessCalls) {
                val rule = if (call.calleeName == "authorize") dslRule(index, call, rules.size, f) else chainRule(index, call, rules.size, f)
                if (rule != null) rules += rule
            }
            if (rules.isNotEmpty()) {
                val scope = chainScope(index, root)
                rules.forEach { it.scope = scope }
                chains += rules
            }
        }
        // web.ignoring().requestMatchers("/x") — полностью вне фильтров безопасности.
        PsiTreeUtil.findChildrenOfType(f.psi, KtCallExpression::class.java)
            .filter { it.calleeName == "ignoring" }
            .forEach { ign ->
                val matcher = (ign.parent?.parent as? KtDotQualifiedExpression)?.selectorExpression as? KtCallExpression
                    ?: ((ign.parent as? KtDotQualifiedExpression)?.parent as? KtDotQualifiedExpression)?.selectorExpression as? KtCallExpression
                if (matcher != null && matcher.calleeName in MATCHER_METHODS) {
                    val pats = matcher.valueArguments.flatMap { index.stringList(it.getArgumentExpression()) ?: emptyList() }
                    if (pats.isNotEmpty()) chains += listOf(SecurityRule(-1, null, pats, false, Access.IGNORED, "ignoring()", matcher, f))
                }
            }
    }
    return chains
}

/**
 * securityMatcher("/ops/...") той же цепочки HttpSecurity: вызовы в той же функции (http.securityMatcher(...).authorizeHttpRequests {…}
 * или отдельным оператором). Без securityMatcher цепочка действует на все пути.
 */
private fun chainScope(index: ProjectIndex, root: KtCallExpression): List<String> {
    val fn = PsiTreeUtil.getParentOfType(root, KtNamedFunction::class.java) ?: return emptyList()
    val out = mutableListOf<String>()
    for (c in PsiTreeUtil.findChildrenOfType(fn, KtCallExpression::class.java)) {
        if (c.calleeName != "securityMatcher" && c.calleeName != "securityMatchers") continue
        if (PsiTreeUtil.isAncestor(root, c, false)) continue
        for (a in c.valueArguments) {
            val e = a.getArgumentExpression() ?: continue
            index.stringValue(e)?.let { out += it; continue }
            index.stringList(e)?.takeIf { it.isNotEmpty() }?.let { out += it; continue }
            val inner = e.unwrapCall() ?: continue
            inner.valueArguments.mapNotNull { index.stringValue(it.getArgumentExpression()) }.firstOrNull()?.let { out += it }
        }
    }
    return out
}

/** X.requestMatchers(GET, "/a", "/b").permitAll() или anyRequest().denyAll(). */
private fun chainRule(index: ProjectIndex, accessCall: KtCallExpression, order: Int, f: KotlinSource): SecurityRule? {
    val access = ACCESS_METHODS[accessCall.calleeName] ?: return null
    val dot = accessCall.parent as? KtDotQualifiedExpression ?: return null
    if (dot.selectorExpression != accessCall) return null
    // Получатель — последний вызов перед доступом: requestMatchers(...) или anyRequest()
    val matcherCall = when (val r = dot.receiverExpression) {
        is KtCallExpression -> r
        is KtDotQualifiedExpression -> r.selectorExpression as? KtCallExpression
        else -> null
    } ?: return null
    return when (matcherCall.calleeName) {
        "anyRequest", "anyExchange" -> SecurityRule(order, null, emptyList(), true, access, accessCall.text, matcherCall, f)
        in MATCHER_METHODS, "pathMatchers" -> {
            var method: String? = null
            val patterns = mutableListOf<String>()
            for (a in matcherCall.valueArguments) {
                val e = a.getArgumentExpression() ?: continue
                val name = (e as? KtNameReferenceExpression)?.getReferencedName() ?: (e as? KtDotQualifiedExpression)?.selectorExpression?.text
                if (name in HTTP_METHODS) { method = name; continue }
                index.stringValue(e)?.let { patterns += it; continue }
                index.stringList(e)?.takeIf { it.isNotEmpty() }?.let { patterns += it; continue }
                // Матчер-объект: AntPathRequestMatcher("/x", "GET"), antMatcher("/x"), mvc.pattern("/x"),
                // PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/x")
                val inner = e.unwrapCall() ?: continue
                if (inner.calleeName in setOf("AntPathRequestMatcher", "antMatcher", "pattern", "matcher", "MvcRequestMatcher", "RegexRequestMatcher", "regexMatcher")) {
                    for (ia in inner.valueArguments.mapNotNull { it.getArgumentExpression() }) {
                        val iname = (ia as? KtNameReferenceExpression)?.getReferencedName() ?: (ia as? KtDotQualifiedExpression)?.selectorExpression?.text
                        val sv = index.stringValue(ia)
                        when {
                            iname in HTTP_METHODS -> method = iname
                            sv != null && sv.uppercase() in HTTP_METHODS -> method = sv.uppercase()
                            sv != null -> patterns += sv
                        }
                    }
                }
            }
            if (patterns.isEmpty()) null else SecurityRule(order, method, patterns, false, access, accessCall.text, matcherCall, f)
        }
        else -> null
    }
}

/** Kotlin DSL: authorize("/x", permitAll), authorize(HttpMethod.GET, "/x", hasRole("A")), authorize(anyRequest, authenticated). */
private fun dslRule(index: ProjectIndex, call: KtCallExpression, order: Int, f: KotlinSource): SecurityRule? {
    val args = call.valueArguments.mapNotNull { it.getArgumentExpression() }
    if (args.size < 2) return null
    val accessExpr = args.last()
    val accessName = (accessExpr as? KtCallExpression)?.calleeName ?: accessExpr.text
    val access = ACCESS_METHODS[accessName] ?: return null
    var method: String? = null
    val patterns = mutableListOf<String>()
    var any = false
    for (e in args.dropLast(1)) {
        val name = (e as? KtNameReferenceExpression)?.getReferencedName() ?: (e as? KtDotQualifiedExpression)?.selectorExpression?.text
        when {
            name in HTTP_METHODS -> method = name
            name == "anyRequest" -> any = true
            else -> index.stringValue(e)?.let { patterns += it } ?: index.stringList(e)?.let { patterns += it }
        }
    }
    if (!any && patterns.isEmpty()) return null
    return SecurityRule(order, method, patterns, any, access, accessExpr.text, call, f)
}

/** Первое подходящее правило для запроса (метод, путь) — как в Spring: первое совпадение побеждает. */
fun effectiveRule(chain: List<SecurityRule>, method: String?, path: String): SecurityRule? =
    chain.filter { it.access != Access.IGNORED }.firstOrNull { r ->
        (r.scope.isEmpty() || r.scope.any { antMatch(it, path) }) &&
        (r.method == null || method == null || r.method == method) && (r.anyRequest || r.patterns.any { antMatch(it, path) })
    }

// ───────────── Сопоставление путей (как AntPathMatcher / PathPattern) ─────────────

/** Совпадение конкретного пути (может содержать {var}) с шаблоном Spring. */
fun antMatch(pattern: String, path: String): Boolean {
    val p = pattern.trim('/').split('/').filter { it.isNotEmpty() }
    val s = path.trim('/').split('/').filter { it.isNotEmpty() }
    return matchSegments(p, 0, s, 0)
}

private fun matchSegments(p: List<String>, pi: Int, s: List<String>, si: Int): Boolean {
    if (pi == p.size) return si == s.size
    if (p[pi] == "**") {
        for (k in si..s.size) if (matchSegments(p, pi + 1, s, k)) return true
        return false
    }
    if (si == s.size) return false
    return segmentMatch(p[pi], s[si]) && matchSegments(p, pi + 1, s, si + 1)
}

private fun segmentMatch(pattern: String, seg: String): Boolean {
    // Переменная пути эндпоинта совпадает только с шаблонным сегментом правила (*, {x}, ?):
    // запрос /visits/123 не подходит под правило /visits/recent — литеральный маршрут Spring выбирает отдельно.
    if (seg.startsWith("{") && seg.endsWith("}")) return pattern.contains('*') || pattern.contains('{') || pattern.contains('?')
    val regex = buildString {
        var i = 0
        while (i < pattern.length) {
            val c = pattern[i]
            when {
                c == '{' -> { val end = pattern.indexOf('}', i); append("[^/]+"); i = if (end < 0) pattern.length else end }
                c == '*' -> append("[^/]*")
                c == '?' -> append("[^/]")
                else -> append(Regex.escape(c.toString()))
            }
            i++
        }
    }
    return Regex(regex).matches(seg)
}

/** Пересекаются ли два шаблона: существует ли путь, подходящий под оба (по образцам). */
fun patternsOverlap(a: String, b: String): Boolean = antMatch(a, sample(b)) || antMatch(b, sample(a))

private fun sample(pattern: String): String =
    pattern.split('/').joinToString("/") { seg ->
        when {
            seg == "**" -> "x"
            seg.contains('*') || seg.contains('{') || seg.contains('?') -> seg.replace(Regex("\\{[^}]*}"), "x").replace("*", "x").replace("?", "x")
            else -> seg
        }
    }

// ───────────── Схема данных: таблицы и owner-колонки ─────────────

class Table(val name: String, val columns: Set<String>, val path: String, val line: Int) {
    /** Колонки владельца записи. Собственный ключ таблицы (account.account_id, accounts.account_id) — не владелец. */
    val ownerColumns: Set<String>
        get() {
            val own = setOf("id", name + "_id", name.removeSuffix("s") + "_id", name.removeSuffix("es") + "_id")
            return (columns.filter { isOwnerColumn(it) } + inferredOwners).filter { it !in own }.toSet()
        }

    /** Колонки, которые другие запросы проекта сравнивают с текущим пользователем (principal.name и т. п.). */
    val inferredOwners: MutableSet<String> = mutableSetOf()
}

private val OWNER_COLUMN = Regex("^(customer|user|owner|client|account|member|tenant|patient|employee|author|created_by|creator|assignee|requester|submitted_by|assigned_to)(_?id|_(login|username|user_name|email|uid|handle|ref))?$|^(driver|rider|passenger|student|teacher|borrower|guest|buyer|renter|subscriber|guardian|beneficiary|holder|reader|person|profile|recipient|sender|courier|seller|member|payer|payee|lender|tenant|passenger)(_?id|_(login|username|user_name|email|uid|ref))$|^created_by_?(user_?)?id$|^owner.*|.*_owner(_id)?$", RegexOption.IGNORE_CASE)

fun isOwnerColumn(name: String): Boolean = OWNER_COLUMN.matches(camelToSnake(name))

fun camelToSnake(s: String): String = s.replace(Regex("([a-z0-9])([A-Z])"), "$1_$2").lowercase()

/** Таблицы из SQL (schema.sql, Flyway V*.sql), Liquibase YAML и JPA @Entity. */
fun extractTables(index: ProjectIndex): Map<String, Table> {
    val out = mutableMapOf<String, Table>()
    val create = Regex("""create\s+table\s+(?:if\s+not\s+exists\s+)?[`"]?(?:\w+\.)?(\w+)[`"]?\s*\((.*?)\)\s*;""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
    for ((path, src) in index.project.textFiles) {
        when {
            path.endsWith(".sql", ignoreCase = true) -> create.findAll(src.text).forEach { m ->
                val cols = splitColumns(m.groupValues[2])
                out.putIfAbsent(m.groupValues[1].lowercase(), Table(m.groupValues[1].lowercase(), cols, path, src.lineOf(m.range.first)))
            }
            (path.endsWith(".yaml") || path.endsWith(".yml")) && src.text.contains("createTable") -> liquibaseTables(path, src.text, src::lineOf).forEach { out.putIfAbsent(it.name, it) }
        }
    }
    for (f in index.project.kotlin) {
        for (cls in PsiTreeUtil.findChildrenOfType(f.psi, KtClass::class.java).filter { it.hasAnnotation("Entity", "Table") }) {
            val tableName = cls.annotation("Table")?.args()?.let { a -> index.stringValue(a["name"] ?: a["value"]) }
                ?: camelToSnake(cls.name ?: continue)
            val cols = mutableSetOf<String>()
            val props = cls.primaryConstructorParameters.filter { it.hasValOrVar() }.map { it.name to it } +
                cls.declarations.filterIsInstance<KtProperty>().map { it.name to it }
            for ((name, decl) in props) {
                name ?: continue
                val typeText = (decl as? KtParameter)?.typeReference?.text ?: (decl as? KtProperty)?.typeReference?.text ?: ""
                val isRelation = (decl as? KtParameter)?.annotationEntries.orEmpty().plus((decl as? KtProperty)?.annotationEntries.orEmpty())
                    .any { it.shortName?.asString() in setOf("ManyToOne", "OneToOne", "JoinColumn") }
                cols += if (isRelation) camelToSnake(name) + "_id" else camelToSnake(name)
                if (isRelation && ProjectIndex.simpleType(typeText).lowercase() in setOf("user", "customer", "client", "account", "owner", "member")) cols += "owner"
            }
            val table = out.getOrPut(tableName.lowercase()) { Table(tableName.lowercase(), cols, f.path, f.line(cls)) }
            out[entityKey(cls.name!!)] = table
        }
    }
    // Таблица без DDL и @Entity, но с data-классом того же имени (ShipmentStore читает «shipment»): колонки берём из класса.
    for (f in index.project.kotlin) {
        for (cls in PsiTreeUtil.findChildrenOfType(f.psi, KtClass::class.java).filter { it.isData() }) {
            val name = camelToSnake(cls.name ?: continue)
            if (name in out) continue
            val cols = cls.primaryConstructorParameters.filter { it.hasValOrVar() }.mapNotNull { it.name }.map { camelToSnake(it) }.toSet()
            out[name] = Table(name, cols, f.path, f.line(cls))
        }
    }
    return out
}

/** Ключ таблицы сущности JPA в карте таблиц: «@ИмяКласса». Реальные имена таблиц не начинаются с @. */
fun entityKey(className: String) = "@$className"

private fun splitColumns(body: String): Set<String> =
    body.split(',').mapNotNull { part ->
        val t = part.trim().split(Regex("\\s+")).firstOrNull()?.trim('`', '"')?.lowercase() ?: return@mapNotNull null
        t.takeIf { it.isNotEmpty() && it !in setOf("primary", "foreign", "constraint", "unique", "check", "key", "index") && it.matches(Regex("\\w+")) }
    }.toSet()

private fun liquibaseTables(path: String, text: String, lineOf: (Int) -> Int): List<Table> {
    val out = mutableListOf<Table>()
    val tableRe = Regex("""tableName:\s*["']?(\w+)""")
    val colRe = Regex("""^\s*-?\s*name:\s*["']?(\w+)""", RegexOption.MULTILINE)
    val blocks = text.split(Regex("""(?=-\s*createTable:)"""))
    var offset = 0
    for (b in blocks) {
        val t = tableRe.find(b)
        if (b.contains("createTable") && t != null) {
            val cols = colRe.findAll(b).map { it.groupValues[1].lowercase() }.filter { it != t.groupValues[1].lowercase() }.toSet()
            out += Table(t.groupValues[1].lowercase(), cols, path, lineOf(offset + t.range.first))
        }
        offset += b.length
    }
    return out
}

/** Таблица и колонки условия WHERE из текста SQL (упрощённо, без полноценного парсера). */
class SqlShape(val tables: List<String>, val whereColumns: Set<String>, val selectedColumns: Set<String>)

fun sqlShape(sql: String): SqlShape {
    val s = sql.replace(Regex("\\s+"), " ")
    val tables = Regex("""\b(?:from|join|update|into)\s+[`"]?(?:\w+\.)?(\w+)""", RegexOption.IGNORE_CASE).findAll(s).map { it.groupValues[1].lowercase() }.toList()
    val where = Regex("""\bwhere\b(.*?)(?:\border\s+by\b|\bgroup\s+by\b|\blimit\b|$)""", RegexOption.IGNORE_CASE).find(s)?.groupValues?.get(1) ?: ""
    val whereCols = Regex("""(?:\w+\.)?(\w+)\s*(?:=|in\b|like\b)""", RegexOption.IGNORE_CASE).findAll(where).map { it.groupValues[1].lowercase() }.toSet()
    val select = Regex("""\bselect\b(.*?)\bfrom\b""", RegexOption.IGNORE_CASE).find(s)?.groupValues?.get(1) ?: ""
    val selected = Regex("""(?:\w+\.)?(\w+|\*)\s*(?:,|$)""").findAll(select.trim()).map { it.groupValues[1].lowercase() }.toSet()
    return SqlShape(tables, whereCols, selected)
}

/** Верх цепочки a.b().c().d() — чтобы Java-стиль http.authorizeRequests().x().y() читался целиком. */
fun topOfChain(e: PsiElement): PsiElement {
    var cur = e
    while (cur.parent is KtDotQualifiedExpression) cur = cur.parent
    return cur
}

/** Лямбда-аргумент или последний аргумент-лямбда вызова. */
fun KtCallExpression.lambda(): KtLambdaExpression? =
    lambdaArguments.firstOrNull()?.getLambdaExpression() ?: valueArguments.lastOrNull()?.getArgumentExpression() as? KtLambdaExpression

fun KtExpression.unwrapCall(): KtCallExpression? = when (this) {
    is KtCallExpression -> this
    is KtDotQualifiedExpression -> selectorExpression as? KtCallExpression
    else -> null
}
