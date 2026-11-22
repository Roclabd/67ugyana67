package codeguard.analyzers.model

import org.jetbrains.kotlin.psi.*
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType

data class SpringModel(
    val endpoints: List<Endpoint>,
    val securityRules: List<SecurityRule>,
    val ignoredPaths: List<Located<String>>,
    val corsConfigs: List<CorsConfig>,
    val repositories: List<DataAccessMethod>,
)

data class Endpoint(
    val method: String?,
    val path: String?,
    val function: String,
    val parameters: List<EndpointParameter>,
    val securityAnnotations: List<SecurityAnnotation>,
    val identityUsages: List<IdentityUsage>,
    val location: Location,
)

enum class ParameterSource { REQUEST_PARAM, PATH_VARIABLE, REQUEST_BODY, REQUEST_HEADER, OTHER }

enum class IdentitySource { PRINCIPAL, AUTHENTICATION, AUTHENTICATION_PRINCIPAL, AUTHORIZATION_HEADER }

data class EndpointParameter(
    val name: String,
    val source: ParameterSource,
    val bindingName: String?,
    val identitySource: IdentitySource?,
    val location: Location,
)

data class SecurityAnnotation(
    val name: String,
    val values: List<String>,
    val location: Location,
)

data class IdentityUsage(
    val parameter: String,
    val receiver: String?,
    val call: String,
    val argumentIndex: Int,
    val location: Location,
)

data class SecurityRule(
    val method: String?,
    val patterns: List<String>,
    val access: String,
    val accessArguments: List<String>,
    val location: Location,
    val matcher: String,
    val chain: Location,
    val hasUnresolvedPatterns: Boolean,
    val accessText: String? = null,
)

data class CorsConfig(
    val origins: List<String>,
    val originPatterns: List<String>,
    val allowCredentials: Boolean?,
    val methods: List<String>,
    val paths: List<String>,
    val location: Location,
)

data class DataAccessMethod(
    val function: String,
    val sql: String,
    val table: String?,
    val whereColumns: List<String>,
    val parameterized: Boolean?,
    val location: Location,
    val tables: List<String> = listOfNotNull(table),
)

internal fun parseSpring(files: List<SourceFile>, kotlin: Map<String, KtFile>): SpringModel {
    val sources = files.mapNotNull { file -> kotlin[file.path]?.let { SpringSource(file, it) } }
    return SpringModel(
        endpoints = sources.flatMap { it.endpoints() },
        securityRules = sources.flatMap { it.securityRules() },
        ignoredPaths = sources.flatMap { it.ignoredPaths() },
        corsConfigs = sources.flatMap { it.corsConfigs() },
        repositories = sources.flatMap { it.repositories() },
    )
}

private val composedMappings = mapOf(
    "GetMapping" to "GET",
    "PostMapping" to "POST",
    "PutMapping" to "PUT",
    "PatchMapping" to "PATCH",
    "DeleteMapping" to "DELETE",
)

private val requestSources = mapOf(
    "RequestParam" to ParameterSource.REQUEST_PARAM,
    "PathVariable" to ParameterSource.PATH_VARIABLE,
    "RequestBody" to ParameterSource.REQUEST_BODY,
    "RequestHeader" to ParameterSource.REQUEST_HEADER,
)

private val httpMethods = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT")
private val authorizationDsl = setOf("authorizeHttpRequests", "authorizeRequests")
private val matcherNames = setOf("requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers", "anyRequest")
private val accessNames = setOf(
    "permitAll", "authenticated", "fullyAuthenticated", "rememberMe", "anonymous", "denyAll",
    "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "hasPermission", "access",
)
private val jdbcTypes = setOf(
    "JdbcTemplate", "JdbcOperations", "NamedParameterJdbcTemplate", "NamedParameterJdbcOperations", "JdbcClient",
)
private val jdbcCalls = setOf(
    "query", "queryForList", "queryForMap", "queryForObject", "queryForRowSet",
    "update", "batchUpdate", "execute", "sql",
)

private class SpringSource(private val source: SourceFile, private val file: KtFile) {
    private val calls = file.collectDescendantsOfType<KtCallExpression>().sortedBy { it.textOffset }
    private val imports = file.importDirectives.mapNotNull { directive ->
        val path = directive.importedFqName?.asString() ?: return@mapNotNull null
        if (directive.isAllUnder) null else (directive.aliasName ?: path.substringAfterLast('.')) to path
    }.toMap()

    fun endpoints(): List<Endpoint> = file.collectDescendantsOfType<KtNamedFunction>().flatMap { function ->
        val owner = function.parent.parent as? KtClassOrObject ?: return@flatMap emptyList()
        val annotations = function.annotationEntries
        val mappings = annotations.filter { it.springName() in composedMappings.keys || it.springName() == "RequestMapping" }
        if (mappings.isEmpty()) return@flatMap emptyList()

        val ownerMappings = owner.annotationEntries.filter { it.springName() == "RequestMapping" }
        val parentPaths = ownerMappings.flatMap { it.mappingPaths() }.ifEmpty { listOf("") }
        val parentMethods = ownerMappings.flatMap { it.mappingMethods() }.distinct()
        val parameters = function.valueParameters.mapNotNull { endpointParameter(it) }
        val security = (owner.annotationEntries + annotations).mapNotNull { annotation ->
            val name = annotation.springName()?.takeIf { it == "PreAuthorize" || it == "Secured" } ?: return@mapNotNull null
            SecurityAnnotation(name, annotation.valueArguments.flatMap { strings(it.getArgumentExpression()).orEmpty() }, location(annotation))
        }
        val identity = identityUsages(function, parameters)
        mappings.flatMap { mapping ->
            val methodList = (parentMethods + mapping.mappingMethods()).distinct().ifEmpty { listOf(null) }
            methodList.flatMap { method ->
                parentPaths.flatMap { parentPath ->
                    mapping.mappingPaths().map { childPath ->
                        Endpoint(method, routePath(parentPath, childPath), nameOf(function), parameters, security, identity, location(mapping))
                    }
                }
            }
        }
    }

    fun securityRules(): List<SecurityRule> = calls.mapNotNull { call ->
        val name = call.callName()
        val statementMatcher = call.receiverCall()?.takeIf { it.callName() in matcherNames }
        val dslArguments = if (name == "authorize") call.arguments() else emptyList()
        val matcher = statementMatcher ?: dslArguments.firstOrNull() as? KtCallExpression
        val accessExpression = dslArguments.lastOrNull()
        val accessCall = accessExpression as? KtCallExpression
        val access = when {
            name == "authorize" && dslArguments.size >= 2 ->
                (accessCall?.callName() ?: (accessExpression as? KtNameReferenceExpression)?.getReferencedName())
                    ?.takeIf { it in accessNames }
            name in accessNames && statementMatcher != null -> name
            else -> null
        } ?: return@mapNotNull null
        val authorization = call.enclosingCall(authorizationDsl)
            ?: matcher?.precedingCall(authorizationDsl)
            ?: return@mapNotNull null

        val matcherName = matcher?.callName()?.takeIf { it in matcherNames }
            ?: (dslArguments.firstOrNull() as? KtNameReferenceExpression)?.getReferencedName()?.takeIf { it == "anyRequest" }
            ?: "authorize"
        val arguments = when {
            matcherName == "anyRequest" -> emptyList()
            name == "authorize" && matcherName == "authorize" -> dslArguments.dropLast(1)
            else -> matcher?.arguments().orEmpty()
        }
        val method = arguments.firstOrNull()?.let { httpMethod(it, "HttpMethod") }
        val patternArguments = if (method != null) arguments.drop(1) else arguments
        val patterns = patternArguments.map { strings(it) }
        val accessArguments = if (name == "authorize") accessCall?.arguments().orEmpty() else call.arguments()
        SecurityRule(
            method, patterns.filterNotNull().flatten(), access,
            accessArguments.flatMap { strings(it).orEmpty() },
            location(matcher ?: call), matcherName, location(authorization), patterns.any { it == null },
            if (name == "authorize") accessExpression?.text else call.text,
        )
    }

    fun ignoredPaths(): List<Located<String>> = calls.flatMap { call ->
        if (call.callName() !in matcherNames || call.receiverCall()?.callName() != "ignoring") {
            return@flatMap emptyList()
        }
        call.arguments().flatMap { argument ->
            strings(argument).orEmpty().map { Located(it, location(argument)) }
        }
    }

    fun corsConfigs(): List<CorsConfig> {
        val registrations = calls.mapNotNull { call ->
            when (call.callName()) {
                "registerCorsConfiguration" -> corsRegistration(call)
                "addMapping" -> corsRegistryMapping(call)
                else -> null
            }
        }
        val annotations = file.collectDescendantsOfType<KtAnnotationEntry>()
            .filter { it.springName() == "CrossOrigin" }
            .mapNotNull { annotation -> annotationCors(annotation) }
        return (registrations + annotations).sortedBy { it.location.line }
    }

    fun repositories(): List<DataAccessMethod> {
        val sqlCalls = calls.mapNotNull { call ->
            if (call.callName() !in jdbcCalls || !isJdbcReceiver(call)) return@mapNotNull null
            val argument = call.namedArgument("sql") ?: call.arguments().firstOrNull() ?: return@mapNotNull null
            val query = sqlText(argument) ?: return@mapNotNull null
            val function = call.parentOfType<KtNamedFunction>() ?: return@mapNotNull null
            val arguments = call.arguments().filterNot { it == argument }
            val bound = when {
                !hasBindMarker(query.text) -> false
                query.dynamic -> null
                call.callName() == "sql" -> generateSequence(call.followingCall()) { it.followingCall() }
                    .firstOrNull { it.callName() in setOf("param", "params", "paramSource") }?.let { true }
                call.callName() in setOf("query", "queryForList", "queryForObject") && arguments.size > 1 -> true
                call.callName() in setOf("update", "batchUpdate") && arguments.isNotEmpty() -> true
                else -> null
            }
            dataAccess(function, query.text, bound, call)
        }
        val jpaQueries = file.collectDescendantsOfType<KtAnnotationEntry>().mapNotNull { annotation ->
            if (annotation.springName() != "Query" || annotation.namedArgument("nativeQuery")?.text != "true") {
                return@mapNotNull null
            }
            val function = annotation.parentOfType<KtNamedFunction>() ?: return@mapNotNull null
            val query = sqlText(annotation.namedArgument("value") ?: annotation.positionalArgument() ?: return@mapNotNull null)
                ?: return@mapNotNull null
            dataAccess(function, query.text, hasBindMarker(query.text).takeUnless { query.dynamic }, annotation)
        }
        return (sqlCalls + jpaQueries).sortedBy { it.location.line }
    }

    private fun endpointParameter(parameter: KtParameter): EndpointParameter? {
        val name = parameter.name ?: return null
        val binding = parameter.annotationEntries.firstOrNull { it.springName() in requestSources.keys }
        val parameterSource = binding?.springName()?.let { requestSources[it] } ?: ParameterSource.OTHER
        val bindingName = binding?.let {
            val value = it.namedArgument("name", "value") ?: it.positionalArgument()
            when {
                value == null -> name
                parameterSource == ParameterSource.REQUEST_HEADER &&
                    canonicalName(value.text) == "org.springframework.http.HttpHeaders.AUTHORIZATION" -> "Authorization"
                else -> strings(value)?.singleOrNull()?.ifEmpty { name }
            }
        }
        val type = canonicalName(parameter.typeReference?.text?.removeSuffix("?").orEmpty())
        val identity = when {
            parameter.annotationEntries.any { it.springName() == "AuthenticationPrincipal" } -> IdentitySource.AUTHENTICATION_PRINCIPAL
            type in setOf("Authentication", "org.springframework.security.core.Authentication") -> IdentitySource.AUTHENTICATION
            type in setOf("Principal", "java.security.Principal") -> IdentitySource.PRINCIPAL
            parameterSource == ParameterSource.REQUEST_HEADER && bindingName.equals("Authorization", ignoreCase = true) ->
                IdentitySource.AUTHORIZATION_HEADER
            else -> null
        }
        return EndpointParameter(name, parameterSource, bindingName, identity, location(parameter))
    }

    private fun identityUsages(function: KtNamedFunction, parameters: List<EndpointParameter>): List<IdentityUsage> {
        val identityNames = parameters.filter { it.identitySource != null }.map { it.name }.toSet()
        if (identityNames.isEmpty()) return emptyList()
        val body = function.bodyExpression ?: return emptyList()
        val bodyCalls = listOfNotNull(body as? KtCallExpression) + body.collectDescendantsOfType<KtCallExpression>()
        return bodyCalls.distinct().filter { it.parentOfType<KtNamedFunction>() == function }.flatMap { call ->
            val callee = call.callName() ?: return@flatMap emptyList()
            val receiver = call.receiver()?.text
            call.arguments().mapIndexedNotNull { index, argument ->
                val name = argument.rootReferenceName() ?: return@mapIndexedNotNull null
                if (name !in identityNames || propertyInScope(argument, name)?.isLocal == true) return@mapIndexedNotNull null
                IdentityUsage(name, receiver, callee, index, location(argument))
            }
        }
    }

    private fun corsRegistration(call: KtCallExpression): CorsConfig? {
        val arguments = call.arguments()
        val argument = arguments.getOrNull(1) ?: return null
        val initialization = (argument as? KtNameReferenceExpression)?.let { reference ->
            propertyInScope(reference, reference.getReferencedName())?.initializer
        } ?: argument
        val apply = (initialization as? KtQualifiedExpression)?.selectorExpression as? KtCallExpression
        val constructor = apply?.receiverCall() ?: initialization as? KtCallExpression
        if (constructor?.callName()?.let { springType(it) } != "CorsConfiguration") return null
        val lambdaBody = apply?.lambdaArguments?.firstOrNull()?.getLambdaExpression()?.bodyExpression
        val assignments = lambdaBody?.statements.orEmpty().filterIsInstance<KtBinaryExpression>()
            .filter { it.operationReference.text == "=" }
        val setters = lambdaBody?.statements.orEmpty().filterIsInstance<KtCallExpression>()
        fun setting(field: String): KtExpression? =
            assignments.lastOrNull { it.left?.text?.removePrefix("this.") == field }?.right
                ?: setters.lastOrNull { it.callName() == "set" + field.replaceFirstChar { char -> char.uppercaseChar() } }
                    ?.arguments()?.firstOrNull()
        fun values(field: String, addMethod: String): List<String> =
            strings(setting(field)).orEmpty() +
                setters.filter { it.callName() == addMethod }.flatMap { setter -> setter.arguments().flatMap { strings(it).orEmpty() } }
        return CorsConfig(
            values("allowedOrigins", "addAllowedOrigin"), values("allowedOriginPatterns", "addAllowedOriginPattern"),
            setting("allowCredentials")?.text?.toBooleanStrictOrNull(), values("allowedMethods", "addAllowedMethod"),
            strings(arguments.firstOrNull()).orEmpty(), location(call),
        )
    }

    private fun corsRegistryMapping(call: KtCallExpression): CorsConfig? {
        val receiverName = call.receiver()?.rootReferenceName() ?: return null
        val type = variableType(call, receiverName)
        if (type != "CorsRegistry") return null
        val settings = generateSequence(call) { it.followingCall() }.toList()
        fun values(name: String): List<String> =
            settings.lastOrNull { it.callName() == name }?.arguments()?.flatMap { strings(it).orEmpty() }.orEmpty()
        val credentials = settings.lastOrNull { it.callName() == "allowCredentials" }
            ?.arguments()?.firstOrNull()?.text?.toBooleanStrictOrNull()
        return CorsConfig(
            values("allowedOrigins"), values("allowedOriginPatterns"), credentials, values("allowedMethods"),
            strings(call.arguments().firstOrNull()).orEmpty(), location(call),
        )
    }

    private fun annotationCors(annotation: KtAnnotationEntry): CorsConfig? {
        val owner = annotation.parent.parent
        val paths = when (owner) {
            is KtNamedFunction -> {
                val functionPaths = owner.annotationEntries.filter {
                    it.springName() in composedMappings.keys || it.springName() == "RequestMapping"
                }.flatMap { it.mappingPaths() }
                val parentPaths = (owner.parent.parent as? KtClassOrObject)?.annotationEntries.orEmpty()
                    .filter { it.springName() == "RequestMapping" }.flatMap { it.mappingPaths() }.ifEmpty { listOf("") }
                parentPaths.flatMap { parentPath -> functionPaths.mapNotNull { routePath(parentPath, it) } }
            }
            is KtClassOrObject -> owner.annotationEntries.filter { it.springName() == "RequestMapping" }
                .flatMap { it.mappingPaths() }.filterNotNull()
            else -> return null
        }
        val origins = annotation.argumentValues("origins", "value")
        val credentialSetting = annotation.namedArgument("allowCredentials")
        return CorsConfig(
            origins.flatMap { strings(it).orEmpty() },
            strings(annotation.namedArgument("originPatterns")).orEmpty(),
            (strings(credentialSetting)?.singleOrNull() ?: credentialSetting?.text)?.toBooleanStrictOrNull(),
            expressions(annotation.namedArgument("methods")).mapNotNull { httpMethod(it, "RequestMethod") },
            paths, location(annotation),
        )
    }

    private fun KtAnnotationEntry.mappingPaths(): List<String?> {
        return argumentValues("path", "value").flatMap { value ->
            strings(value)?.map { path -> path.takeUnless { it.contains("\${") } } ?: listOf(null)
        }.ifEmpty { listOf("") }
    }

    private fun KtAnnotationEntry.mappingMethods(): List<String> {
        composedMappings[springName()]?.let { return listOf(it) }
        return expressions(namedArgument("method")).mapNotNull { httpMethod(it, "RequestMethod") }
    }

    private fun httpMethod(element: KtExpression, enumName: String): String? {
        val name = element.text
        val canonical = canonicalName(name)
        val method = canonical.substringAfterLast('.').takeIf { it in httpMethods } ?: return null
        val qualifier = canonical.substringBeforeLast('.', "")
        return method.takeIf {
            qualifier.substringAfterLast('.') == enumName || file.importDirectives.any { directive ->
                directive.isAllUnder && directive.importedFqName?.shortName()?.asString() == enumName
            }
        }
    }

    private fun KtAnnotationEntry.springName(): String? {
        val spelling = typeReference?.text ?: return null
        val name = canonicalName(spelling)
        return name.substringAfterLast('.').takeIf {
            '.' !in name || name.startsWith("org.springframework.")
        }
    }

    private fun springType(spelling: String): String? {
        val name = canonicalName(spelling)
        return name.substringAfterLast('.').takeIf { '.' !in name || name.startsWith("org.springframework.") }
    }

    private fun canonicalName(spelling: String): String {
        val first = spelling.substringBefore('.')
        val imported = imports[first] ?: return spelling
        return imported + spelling.removePrefix(first)
    }

    private fun variableType(element: KtElement, name: String): String? {
        val property = propertyInScope(element, name)
        if (property != null) {
            return property.typeReference?.text?.removeSuffix("?")?.let { springType(it) }
                ?: (property.initializer as? KtCallExpression)?.callName()?.let { springType(it) }
        }
        val parameter = generateSequence(element.parent) { it.parent }.firstNotNullOfOrNull { owner ->
            when (owner) {
                is KtNamedFunction -> owner.valueParameters.firstOrNull { it.name == name }
                is KtClass -> owner.primaryConstructorParameters.firstOrNull { it.hasValOrVar() && it.name == name }
                else -> null
            }
        }
        return parameter?.typeReference?.text?.removeSuffix("?")?.let { springType(it) }
    }

    private fun isJdbcReceiver(call: KtCallExpression): Boolean {
        val receiver = call.receiver() ?: return false
        if (receiver is KtCallExpression) return receiver.callName()?.let { springType(it) } in jdbcTypes
        val name = receiver.rootReferenceName() ?: return false
        if (receiver is KtQualifiedExpression && receiver.receiverExpression !is KtThisExpression) return false
        return variableType(call, name) in jdbcTypes
    }

    private fun dataAccess(function: KtNamedFunction, sql: String, bound: Boolean?, element: KtElement): DataAccessMethod {
        val structuralSql = sqlStrings.replace(sql, " ")
        val tables = sqlTable.findAll(structuralSql).map { it.groupValues[1] }.distinct().toList()
        val where = sqlWhere.find(structuralSql)?.groupValues?.get(1).orEmpty()
        val columns = sqlWhereColumn.findAll(where).map { it.groupValues[1].substringAfterLast('.') }.distinct().toList()
        return DataAccessMethod(nameOf(function), sql, tables.singleOrNull(), columns, bound, location(element), tables)
    }

    private fun nameOf(function: KtNamedFunction): String = function.fqName?.asString() ?: function.name.orEmpty()

    private fun strings(expression: KtExpression?): List<String>? = when (expression) {
        is KtStringTemplateExpression -> sqlText(expression)?.takeUnless { it.dynamic }?.let { listOf(it.text) }
        is KtCollectionLiteralExpression -> expression.getInnerExpressions().flatMapStrings()
        is KtCallExpression -> if (expression.callName() in setOf("arrayOf", "listOf", "setOf")) {
            expression.arguments().flatMapStrings()
        } else {
            null
        }
        else -> null
    }

    private fun List<KtExpression>.flatMapStrings(): List<String>? {
        val values = map { strings(it) }
        return if (values.any { it == null }) null else values.filterNotNull().flatten()
    }

    private fun sqlText(expression: KtExpression, visited: Set<KtProperty> = emptySet()): SqlText? {
        return when (expression) {
            is KtStringTemplateExpression -> SqlText(
                expression.entries.joinToString("") { entry ->
                    if (entry is KtEscapeStringTemplateEntry) entry.unescapedValue else entry.text
                },
                expression.entries.any { it !is KtLiteralStringTemplateEntry && it !is KtEscapeStringTemplateEntry },
            )
            is KtNameReferenceExpression -> {
                val property = propertyInScope(expression, expression.getReferencedName()) ?: return null
                val initializer = property.initializer?.takeUnless { property.isVar || property in visited } ?: return null
                sqlText(initializer, visited + property)
            }
            is KtQualifiedExpression -> {
                val transformation = (expression.selectorExpression as? KtCallExpression)?.callName()
                val text = sqlText(expression.receiverExpression, visited) ?: return null
                when (transformation) {
                    "trimIndent" -> text.copy(text = text.text.trimIndent())
                    "trimMargin" -> text.copy(text = text.text.trimMargin())
                    else -> null
                }
            }
            is KtBinaryExpression -> {
                if (expression.operationReference.text != "+") return null
                val left = expression.left?.let { sqlText(it, visited) } ?: return null
                val right = expression.right?.let { sqlText(it, visited) }
                SqlText(left.text + (right?.text ?: expression.right?.text.orEmpty()), left.dynamic || right?.dynamic != false)
            }
            else -> null
        }
    }

    private fun location(element: KtElement): Location = source.location(element.textOffset)
}

private data class SqlText(val text: String, val dynamic: Boolean)

private val sqlStrings = Regex("'(?:''|[^'])*'|--[^\\r\\n]*|/\\*[\\s\\S]*?\\*/")
private val sqlTable = Regex("\\b(?:FROM|JOIN|UPDATE|INTO)\\s+([A-Za-z_]\\w*(?:\\.[A-Za-z_]\\w*)*)", RegexOption.IGNORE_CASE)
private val sqlWhere = Regex("\\bWHERE\\s+([\\s\\S]*?)(?=\\b(?:ORDER\\s+BY|GROUP\\s+BY|RETURNING|LIMIT|OFFSET)\\b|$)", RegexOption.IGNORE_CASE)
private val sqlWhereColumn = Regex("\\b([A-Za-z_]\\w*(?:\\.[A-Za-z_]\\w*)*)\\s*(?:[<=>!]|\\b(?:IN|IS|LIKE|BETWEEN)\\b)", RegexOption.IGNORE_CASE)
private val bindMarker = Regex("\\?|(?<!:):[A-Za-z_]\\w*")

private fun hasBindMarker(sql: String): Boolean = bindMarker.containsMatchIn(sqlStrings.replace(sql, " "))

private fun routePath(parent: String?, child: String?): String? {
    if (parent == null || child == null) return null
    if (child.isEmpty() && parent.isNotEmpty()) return "/" + parent.trimStart('/')
    return "/" + listOf(parent.trim('/'), child.trimStart('/')).filter { it.isNotEmpty() }.joinToString("/")
}

private fun KtCallExpression.callName(): String? = (calleeExpression as? KtNameReferenceExpression)?.getReferencedName()

private fun KtCallExpression.receiver(): KtExpression? = (parent as? KtQualifiedExpression)
    ?.takeIf { it.selectorExpression == this }?.receiverExpression

private fun KtCallExpression.receiverCall(): KtCallExpression? = when (val receiver = receiver()) {
    is KtCallExpression -> receiver
    is KtQualifiedExpression -> receiver.selectorExpression as? KtCallExpression
    else -> null
}

private fun KtCallExpression.followingCall(): KtCallExpression? {
    val expression = (parent as? KtQualifiedExpression)?.takeIf { it.selectorExpression == this } ?: this
    return (expression.parent as? KtQualifiedExpression)
        ?.takeIf { it.receiverExpression == expression }?.selectorExpression as? KtCallExpression
}

private fun KtCallExpression.precedingCall(names: Set<String>): KtCallExpression? =
    generateSequence(receiverCall()) { it.receiverCall() }.firstOrNull { it.callName() in names }

private fun KtCallExpression.enclosingCall(names: Set<String>): KtCallExpression? =
    generateSequence(parent) { it.parent }.filterIsInstance<KtCallExpression>().firstOrNull { it.callName() in names }

private inline fun <reified T : KtElement> KtElement.parentOfType(): T? =
    generateSequence(parent) { it.parent }.filterIsInstance<T>().firstOrNull()

private fun KtCallElement.namedArgument(vararg names: String): KtExpression? =
    valueArguments.firstOrNull { it.getArgumentName()?.asName?.asString() in names }?.getArgumentExpression()

private fun KtCallElement.argumentValues(vararg names: String): List<KtExpression> =
    namedArgument(*names)?.let { listOf(it) }
        ?: valueArguments.filter { it.getArgumentName() == null }.mapNotNull { it.getArgumentExpression() }

private fun KtCallElement.positionalArgument(): KtExpression? =
    valueArguments.firstOrNull { it.getArgumentName() == null }?.getArgumentExpression()

private fun KtCallExpression.arguments(): List<KtExpression> = valueArguments.mapNotNull { it.getArgumentExpression() }

private fun expressions(expression: KtExpression?): List<KtExpression> = when (expression) {
    is KtCollectionLiteralExpression -> expression.getInnerExpressions()
    is KtCallExpression -> if (expression.callName() == "arrayOf") expression.arguments() else listOf(expression)
    null -> emptyList()
    else -> listOf(expression)
}

private fun KtExpression.rootReferenceName(): String? = when (this) {
    is KtNameReferenceExpression -> getReferencedName()
    is KtQualifiedExpression -> when {
        selectorExpression !is KtNameReferenceExpression -> null
        receiverExpression is KtThisExpression -> (selectorExpression as? KtNameReferenceExpression)?.getReferencedName()
        else -> receiverExpression.rootReferenceName()
    }
    is KtParenthesizedExpression -> expression?.rootReferenceName()
    else -> null
}

private fun propertyInScope(use: KtElement, name: String): KtProperty? =
    generateSequence(use.parent) { it.parent }.firstNotNullOfOrNull { scope ->
        val declarations = when (scope) {
            is KtBlockExpression -> scope.statements.filter { it.textOffset < use.textOffset }
            is KtClassBody -> scope.declarations
            is KtFile -> scope.declarations
            else -> emptyList()
        }
        declarations.filterIsInstance<KtProperty>().lastOrNull { it.name == name }
    }
