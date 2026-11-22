package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceFile
import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtArrayAccessExpression
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtCallElement
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtClassBody
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDeclarationWithBody
import org.jetbrains.kotlin.psi.KtElement
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedDeclaration
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectDeclaration
import org.jetbrains.kotlin.psi.KtParameter
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.KtThisExpression
import java.util.Base64

internal fun scanKotlinSecrets(model: ProjectModel): SecretRuleResult {
    val sources = model.files.associateBy(SourceFile::path)
    val table = ConstantTable()
    val scanners = model.kotlin.map { (path, file) -> KotlinSecretScanner(sources.getValue(path), file, table) }
    table.register(scanners)
    val results = scanners.map { it.scan() }
    return SecretRuleResult(results.flatMap { it.candidates }, results.flatMap { it.dismissed })
}

/**
 * Общая таблица констант проекта: `const val` верхнего уровня, в `object` и `companion object` по всем Kotlin-файлам.
 * Ключ — квалифицированное имя (`pkg.NAME`, `pkg.Owner.NAME`); неоднозначные (дубли) отбрасываются.
 */
private class ConstantTable {
    class Entry(val property: KtProperty, val scanner: KotlinSecretScanner)

    private val entries = mutableMapOf<String, Entry?>()

    class FunctionEntry(val function: KtNamedFunction, val scanner: KotlinSecretScanner)

    private val functions = mutableMapOf<String, FunctionEntry?>()

    /** Функция без параметров в объекте, классе, companion или на верхнем уровне: ключ `pkg.Owner.fn` / `pkg.fn`. */
    fun function(key: String): FunctionEntry? = functions[key]

    private fun addFunction(key: String, function: KtNamedFunction, scanner: KotlinSecretScanner) {
        if (function.name == null || function.valueParameters.isNotEmpty() || function.receiverTypeReference != null) return
        if (function.bodyExpression == null) return
        functions[key] = if (key in functions) null else FunctionEntry(function, scanner)
    }

    private fun addFunctions(owner: String, container: org.jetbrains.kotlin.psi.KtClassOrObject, scanner: KotlinSecretScanner) {
        for (function in container.declarations.filterIsInstance<KtNamedFunction>()) addFunction("$owner.${function.name}", function, scanner)
    }

    fun register(scanners: List<KotlinSecretScanner>) {
        for (scanner in scanners) {
            val prefix = scanner.packageName.let { if (it.isEmpty()) "" else "$it." }
            for (declaration in scanner.ktFile.declarations) {
                when (declaration) {
                    is KtProperty -> add("$prefix${declaration.name}", declaration, scanner)
                    is KtNamedFunction -> addFunction("$prefix${declaration.name}", declaration, scanner)
                    is KtObjectDeclaration -> {
                        addMembers("$prefix${declaration.name}", declaration, scanner)
                        addFunctions("$prefix${declaration.name}", declaration, scanner)
                    }
                    is KtClass -> {
                        declaration.companionObjects.singleOrNull()?.let {
                            addMembers("$prefix${declaration.name}", it, scanner)
                            addFunctions("$prefix${declaration.name}", it, scanner)
                        }
                        addFunctions("$prefix${declaration.name}", declaration, scanner)
                    }
                }
            }
        }
    }

    private fun addMembers(owner: String, container: KtObjectDeclaration, scanner: KotlinSecretScanner) {
        for (property in container.declarations.filterIsInstance<KtProperty>()) add("$owner.${property.name}", property, scanner)
    }

    private fun add(key: String, property: KtProperty, scanner: KotlinSecretScanner) {
        if (!property.hasModifier(KtTokens.CONST_KEYWORD) || property.name == null) return
        entries[key] = if (key in entries) null else Entry(property, scanner)
    }

    operator fun get(key: String): Entry? = entries[key]
}

private class KotlinSecretScanner(
    private val source: SourceFile,
    private val file: KtFile,
    private val table: ConstantTable = ConstantTable(),
) {
    val ktFile: KtFile get() = file
    val packageName: String get() = file.packageFqName.asString()
    private val declaredNames: Set<String> by lazy {
        (PsiTreeUtil.findChildrenOfType(file, KtProperty::class.java).mapNotNull { it.name } +
            PsiTreeUtil.findChildrenOfType(file, KtParameter::class.java).mapNotNull { it.name }).toSet()
    }
    private val candidates = mutableListOf<SecretCandidate>()
    private val dismissed = mutableListOf<SecretDismissal>()
    private var remainingFoldSteps = 0

    fun scan(): SecretRuleResult {
        for (property in children<KtProperty>()) {
            checkBinding(property.name, property.initializer ?: getterExpression(property), property)
        }
        for (parameter in children<KtParameter>()) {
            checkBinding(parameter.name, parameter.defaultValue, parameter)
        }
        for (expression in children<KtBinaryExpression>()) {
            when (expression.operationToken) {
                KtTokens.EQ -> {
                    val target = expression.left?.unwrap()
                    if (target is KtArrayAccessExpression) {
                        val key = fold(target.indexExpressions.singleOrNull())?.value
                        key?.let(::secretKind)?.let { checkSink(it, expression.right, expression) }
                    } else {
                        checkBinding(expression.left?.referenceName(), expression.right, expression)
                    }
                }
                KtTokens.EQEQ, KtTokens.EQEQEQ -> checkComparison(expression.left, expression.right, expression)
                KtTokens.ELVIS -> if (isSecretRead(expression.left, expression)) {
                    checkFallback(expression.right, expression, expression.left)
                }
                KtTokens.IDENTIFIER -> if (expression.operationReference.text == "to") {
                    val key = fold(expression.left)?.value ?: headerConstant(expression.left) ?: continue
                    (headerKind(key) ?: secretKind(key) ?: weakSecretKind(key, fold(expression.right)?.value))
                        ?.let { checkSink(it, expression.right, expression) }
                }
            }
        }
        for (call in children<KtCallExpression>()) {
            val sink = call.secretArgument()
            if (sink != null) checkSink(sink.kind, sink.value, call)
            checkFallbackCall(call)
            if (call.name() == "equals") {
                val receiver = call.receiver()
                if (receiver != null) checkComparison(receiver, call.argument(0, "other"), call)
            }
        }
        for (annotation in children<KtAnnotationEntry>()) {
            checkValueAnnotation(annotation)
        }
        for (expression in children<org.jetbrains.kotlin.psi.KtIfExpression>()) {
            checkIfFallback(expression)
        }
        for (function in children<KtNamedFunction>()) {
            checkReturnedToken(function)
        }
        scanLiterals()
        val recoverable = candidates.filter { it.kind == "recoverable-token" }
        val unique = candidates.distinctBy { Triple(it.kind, it.value, it.location) }.filterNot { candidate ->
            candidate.kind in directSecretKinds && recoverable.any { reconstructed ->
                candidate.value.withoutBearer() == reconstructed.value &&
                    candidate.evidence.any { it in reconstructed.evidence }
            }
        }
        return SecretRuleResult(unique, dismissed.distinct())
    }

    private fun checkBinding(name: String?, expression: KtExpression?, declaration: KtElement) {
        if (name != null && checkPluralBinding(name, expression, declaration)) return
        var kind = name?.let(::secretKind)
        val weak = if (kind == null && name != null) weakSecretName(name) else null
        if (kind == null && weak == null && expression !is KtStringTemplateExpression) return
        val value = fold(expression) ?: return
        if (kind == null && weak != null && looksLikeSecretValue(value.value, weak.minLength)) kind = weak.kind
        if (kind == null && name != null && bearerLiteral(value.value) != null && embeddedCredential(value.value) == null) {
            val site = location(declaration)
            record("configuration-token", bearerLiteral(value.value)!!, site, value.evidence + site)
            return
        }
        val embedded = embeddedCredential(value.value)
        val shape = if (embedded == null && kind == null) knownTokenShape(value.value) else null
        val credentialKind = embedded?.first ?: kind ?: shape?.first ?: return
        if (headerKind(value.value, bare = false) != null) return
        val primary = location(declaration)
        if (embedded == null && kind != null && inConfigurationProperties(declaration)) {
            // Значение по умолчанию поля класса настроек действует, когда конфигурация не задана, — это запасной секрет.
            record("secret-fallback", value.value, primary, value.evidence + primary)
            return
        }
        if (embedded == null && kind != null && kind != "password" && value.transformed && declaration is KtProperty && !declaration.hasModifier(KtTokens.CONST_KEYWORD)) {
            // Секрет собран из фрагментов (buildString, concatToString, склейка): восстанавливается из констант.
            val bound = (if (declaration.getter != null) value.evidence else value.evidence + primary).filter { it.path == source.path }
            val first = bound.minOf { it.line }
            val last = bound.maxOf { it.endLine ?: it.line }
            record("recoverable-token", value.value.trim(), Location(source.path, first, last.takeIf { it > first }), value.evidence + primary)
            return
        }
        record(credentialKind, embedded?.second ?: shape?.second ?: value.value, primary, value.evidence + primary)
    }

    /** `val apiKeys = listOf("a1…", "b2…")`: имя во множественном числе, секреты в элементах коллекции. */
    private fun checkPluralBinding(name: String, expression: KtExpression?, declaration: KtElement): Boolean {
        val call = expression?.unwrap() as? KtCallExpression ?: return false
        if (call.name() !in collectionFactories || call.name() in setOf("charArrayOf", "ArrayList")) return false
        val last = name.replace(Regex("(?<=[a-z0-9])(?=[A-Z])"), "-").lowercase().substringAfterLast('-')
        if (last !in setOf("keys", "tokens", "secrets", "passwords", "apikeys")) return false
        val singular = name.dropLast(1)
        for (argument in call.valueArguments) {
            val element = argument.getArgumentExpression() ?: continue
            val value = fold(element)?.value ?: continue
            val kind = weakSecretKind(singular, value) ?: continue
            val site = location(element)
            record(kind, value, site, listOf(site))
        }
        return true
    }

    /** Тело геттера `val x get() = …` / `get() { return … }` или `val x by lazy { … }`. */
    private fun getterExpression(property: KtProperty): KtExpression? {
        lazyBody(property)?.let { return it }
        val body = property.getter?.bodyExpression ?: return null
        if (body !is KtBlockExpression) return body
        return (body.statements.singleOrNull() as? org.jetbrains.kotlin.psi.KtReturnExpression)?.returnedExpression
    }

    /** Поле класса `@ConfigurationProperties`: параметр основного конструктора или свойство в теле класса. */
    private fun inConfigurationProperties(declaration: KtElement): Boolean {
        val owner = when (declaration) {
            is KtParameter -> (declaration.parent?.parent as? org.jetbrains.kotlin.psi.KtPrimaryConstructor)?.parent as? KtClass
            is KtProperty -> if (declaration.isLocal) null else (declaration.parent as? KtClassBody)?.parent as? KtClass
            else -> null
        } ?: return false
        return owner.annotationEntries.any { it.shortName?.asString() == "ConfigurationProperties" }
    }

    /** `password == "x"`, `"x" == password`, `pwd.equals("x")`. */
    private fun checkComparison(left: KtExpression?, right: KtExpression?, site: KtElement) {
        for ((name, literal) in listOf(left to right, right to left)) {
            val kind = name?.unwrap()?.referenceName()?.let(::secretKind) ?: continue
            if (literal?.unwrap() !is KtStringTemplateExpression) continue
            checkSink(kind, literal, site)
            return
        }
    }

    /** Known credential shapes inside any string literal, regardless of the name it is bound to. */
    private fun scanLiterals() {
        val taken = candidates.flatMap { c -> c.evidence.map { it.line } + c.location.line }.toMutableSet()
        for (template in children<KtStringTemplateExpression>()) {
            val value = fold(template)?.value ?: continue
            val credential = embeddedCredential(value) ?: knownTokenShape(value) ?: continue
            val site = location(template)
            if (!taken.add(site.line)) continue
            record(credential.first, credential.second, site, listOf(site))
        }
    }

    private fun checkSink(sinkKind: String, expression: KtExpression?, sink: KtElement) {
        val value = fold(expression) ?: return
        // Authorization: Key <ключ> / ApiKey <ключ> — ключ API, а не токен доступа.
        val kind = if (sinkKind == "configuration-token" && apiKeyScheme.containsMatchIn(value.value)) "api-key" else sinkKind
        val credential = value.value.withoutBearer()
        val sinkSite = location(sink)
        val evidence = value.evidence + sinkSite
        val foreign = value.evidence.filter { it.path != source.path }.ifEmpty { null }
        val primary = if (foreign != null) {
            foreign.minBy { it.line }.let { Location(it.path, it.line) }
        } else {
            Location(source.path, value.evidence.minOf { it.line })
        }
        if (kind != "password" && value.transformed) {
            val end = evidence.filter { it.path == primary.path }.maxOf { it.endLine ?: it.line }
            record("recoverable-token", credential, primary.copy(endLine = end), evidence)
        } else {
            val existing = candidates.indexOfFirst {
                it.kind in directSecretKinds && it.value.withoutBearer() == credential &&
                    it.evidence.any { site -> site in value.evidence }
            }
            if (existing < 0) {
                record(kind, credential, primary, evidence)
            } else {
                val finding = candidates[existing]
                candidates[existing] = SecretCandidate(
                    finding.kind, finding.value, finding.location, (finding.evidence + sinkSite).distinct(),
                )
            }
        }
    }

    private fun checkFallbackCall(call: KtCallExpression) {
        val receiver = call.receiver()
        when (call.name()) {
            "getOrDefault" -> if ((receiver?.unwrap() as? KtCallExpression)?.name() == "runCatching") {
                val body = (receiver.unwrap() as KtCallExpression).lambdaArguments.singleOrNull()?.getLambdaExpression()
                    ?.bodyExpression?.statements?.lastOrNull()
                if (isSecretRead(body, call)) checkFallback(call.argument(0, "defaultValue"), call, body)
            } else {
                val key = call.argument(0, "key")
                if (environmentSource(receiver) && credentialKey(key, call)) {
                    checkFallback(call.argument(1, "defaultValue"), call, receiver)
                }
            }
            "getProperty", "getenv" -> {
                val fallback = call.argument(1, "defaultValue", "default")
                if (fallback != null && environmentAccessor(call) && credentialKey(call.argument(0, "key", "name"), call)) {
                    checkFallback(fallback, call, receiver)
                }
            }
            "orElse" -> if (isSecretRead(receiver, call)) {
                checkFallback(call.argument(0, "value", "defaultValue"), call, receiver)
            }
            "ifBlank", "ifEmpty" -> if (isSecretRead(receiver, call)) {
                val lambda = call.lambdaArguments.singleOrNull()?.getLambdaExpression()
                    ?: call.argument(0, "defaultValue") as? KtLambdaExpression
                val fallback = lambda?.bodyExpression?.statements?.singleOrNull()
                checkFallback(fallback, call, receiver)
            }
        }
    }

    private fun isSecretRead(expression: KtExpression?, context: KtElement, depth: Int = 0): Boolean {
        if (depth >= maxFoldDepth) return false
        val read = expression?.unwrap() ?: return false
        val call = when (read) {
            is KtCallExpression -> read
            is KtQualifiedExpression -> (read.selectorExpression as? KtCallExpression) ?: return configHolderRead(read)
            is org.jetbrains.kotlin.psi.KtPostfixExpression -> return isSecretRead(read.baseExpression, context, depth + 1)
            is KtArrayAccessExpression -> return environmentSource(read.arrayExpression)
                && credentialKey(read.indexExpressions.singleOrNull(), context)
            is KtNameReferenceExpression -> {
                val property = propertyInScope(read, read.getReferencedName()) ?: return false
                return isSecretRead(property.initializer, context, depth + 1)
            }
            else -> return false
        } ?: return false
        return when {
            environmentAccessor(call) -> credentialKey(call.argument(0, "key", "name"), context)
            call.name() in passThroughReads -> isSecretRead(call.receiver(), context, depth + 1)
            call.name() == "ofNullable" -> isSecretRead(call.argument(0, "value"), context, depth + 1)
            call.name() != null && call.valueArguments.isNotEmpty() && readsEnvironment(call.name()!!) ->
                credentialKey(call.argument(0, "key", "name"), context)
            call.name() == "get"|| call.name() == "getOrNull" -> {
                val receiver = call.receiver()
                (environmentSource(receiver) && credentialKey(call.argument(0, "key"), context)) ||
                    isSecretRead(receiver, context, depth + 1)
            }
            else -> false
        }
    }

    /** Функция проекта (или привычное имя обёртки), которая читает getenv / getProperty. */
    private fun readsEnvironment(name: String): Boolean {
        if (name in environmentWrapperNames) return true
        return PsiTreeUtil.findChildrenOfType(file, KtNamedFunction::class.java).any { function ->
            function.name == name && PsiTreeUtil.findChildrenOfType(function, KtCallExpression::class.java).any {
                it.name() == "getenv" || it.name() == "getProperty" || it.name() == "environmentVariable"
            }
        }
    }

    /** `if (v != null) v else "lit"`, `if (v == null) "lit" else v`, `if (v.isNullOrBlank()) "lit" else v`. */
    private fun checkIfFallback(expression: org.jetbrains.kotlin.psi.KtIfExpression) {
        val condition = expression.condition?.unwrap() ?: return
        val thenBranch = expression.then?.let(::single) ?: return
        val elseBranch = expression.`else`?.let(::single) ?: return
        val subject: KtExpression
        val presentBranch: KtExpression
        val fallbackBranch: KtExpression
        if (condition is KtBinaryExpression && (condition.operationToken == KtTokens.EXCLEQ || condition.operationToken == KtTokens.EQEQ) &&
            (condition.right?.text == "null" || condition.left?.text == "null")) {
            subject = (if (condition.right?.text == "null") condition.left else condition.right)?.unwrap() ?: return
            val notNull = condition.operationToken == KtTokens.EXCLEQ
            presentBranch = if (notNull) thenBranch else elseBranch
            fallbackBranch = if (notNull) elseBranch else thenBranch
        } else {
            val call = (condition as? KtQualifiedExpression)?.selectorExpression as? KtCallExpression ?: return
            if (call.name() !in setOf("isNullOrBlank", "isNullOrEmpty")) return
            subject = (condition as KtQualifiedExpression).receiverExpression.unwrap() ?: return
            presentBranch = elseBranch
            fallbackBranch = thenBranch
        }
        if (presentBranch.unwrap()?.text != subject.text || !isSecretRead(subject, expression)) return
        checkFallback(fallbackBranch, expression, subject)
    }

    private fun single(expression: KtExpression): KtExpression? =
        (expression as? KtBlockExpression)?.statements?.singleOrNull() ?: expression

    private fun environmentAccessor(call: KtCallExpression): Boolean {
        val receiver = call.receiver()?.text.orEmpty()
        return when (call.name()) {
            "getenv" -> receiver.isEmpty() || receiver == "System" || receiver == "java.lang.System"
            "getProperty" -> receiver.substringAfterLast('.').lowercase() in setOf("system", "environment", "env")
            "environmentVariable", "systemProperty", "gradleProperty" -> receiver.substringAfterLast('.') == "providers"
            else -> false
        }
    }

    private fun environmentSource(expression: KtExpression?, depth: Int = 0): Boolean {
        if (depth >= maxFoldDepth) return false
        val read = expression?.unwrap() ?: return false
        val call = read as? KtCallExpression ?: (read as? KtQualifiedExpression)?.selectorExpression as? KtCallExpression
        if (call?.name() == "getenv" && call.valueArguments.isEmpty()) return environmentAccessor(call)
        val name = read.referenceName() ?: return false
        if (name.lowercase() in setOf("env", "environment", "envvars", "dotenv", "dotenvs")) return true
        val property = propertyInScope(read, name) ?: return false
        return environmentSource(property.initializer, depth + 1)
    }

    private fun credentialKey(key: KtExpression?, context: KtElement): Boolean {
        val name = fold(key)?.value ?: key?.referenceName()
        if (name?.let(::secretKind) != null) return true
        for (parent in generateSequence(context.parent) { it.parent }) {
            when (parent) {
                is KtProperty -> return parent.name?.let(::secretKind) != null
                is KtParameter -> return parent.name?.let(::secretKind) != null
                is KtCallExpression -> if (parent.secretArgument() != null) return true
                is KtBlockExpression, is KtNamedFunction -> return false
            }
        }
        return false
    }

    private fun checkFallback(expression: KtExpression?, site: KtElement, read: KtExpression?) {
        val primary = location(site)
        val value = fold(expression)
        if (value == null) {
            dismissed += SecretDismissal("secret-fallback", primary, "non-literal-fallback")
            return
        }
        record("secret-fallback", value.value, primary, listOfNotNull(read?.let(::location), primary) + value.evidence)
    }

    private fun checkValueAnnotation(annotation: KtAnnotationEntry) {
        val name = annotation.shortName?.asString() ?: return
        val spelling = annotation.typeReference?.text ?: return
        val resolved = if ('.' in spelling) spelling else importedName(name)
        if (resolved != "org.springframework.beans.factory.annotation.Value" && (resolved != null || name != "Value")) return
        val expression = annotation.argument(0, "value")
        val value = fold(expression) ?: return
        val owner = annotation.parent.parent as? KtNamedDeclaration
        val placeholder = springPlaceholder.matchEntire(value.value.trim()) ?: run {
            val literalKind = owner?.name?.let(::secretKind)
            if (literalKind != null && !value.value.contains("\${") && !value.value.contains("#{")) {
                val site = location(annotation)
                record(literalKind, value.value, site, value.evidence + site)
            }
            return
        }
        val groups = placeholder.groups
        if (secretKind(groups[1]!!.value) == null && owner?.name?.let(::secretKind) == null) return
        val primary = location(annotation)
        val fallback = groups[2]?.value
        if (fallback == null) {
            dismissed += SecretDismissal("secret-fallback", primary, "environment-reference")
        } else {
            record("secret-fallback", fallback, primary, value.evidence + primary)
        }
    }

    private fun record(kind: String, value: String, primary: Location, evidence: List<Location>) {
        val credential = value.withoutBearer()
        val substitution = springPlaceholder.matchEntire(credential.trim())
        val fallback = substitution?.groups?.get(2)?.value
        val actualKind = if (fallback != null) "secret-fallback" else kind
        val reason = when {
            substitution != null && fallback == null -> "environment-reference"
            fallback != null && springPlaceholder.containsMatchIn(fallback) -> "non-literal-fallback"
            isPlaceholder(fallback ?: credential) -> "placeholder"
            kind == "password" && encodedPassword.matches(credential) -> "encoded-hash"
            else -> null
        }
        if (reason != null) {
            dismissed += SecretDismissal(actualKind, primary, reason)
        } else {
            candidates += SecretCandidate(actualKind, fallback ?: value, primary, evidence.distinct().sortedWith(compareBy<Location>({ it.path != primary.path }, { it.path }, { it.line })))
        }
    }

    private fun KtCallExpression.secretArgument(): SecretArgument? {
        return when (name()) {
            "put", "putIfAbsent", "setProperty", "property", "setAttribute" -> {
                val key = fold(argument(0, "key", "name"))?.value ?: return null
                val kind = secretKind(key) ?: weakSecretKind(key, fold(argument(1, "value"))?.value) ?: return null
                SecretArgument(kind, argument(1, "value"))
            }
            "setBearerAuth", "bearerAuth", "BearerTokens" -> SecretArgument("configuration-token", argument(0, "token", "accessToken"))
            "HMAC256", "HMAC384", "HMAC512", "hmacShaKeyFor" -> SecretArgument("configuration-token", argument(0, "secret", "bytes"))
            "SecretKeySpec" -> if (valueArguments.size >= 2 && fold(argument(1, "algorithm")) != null) {
                SecretArgument("configuration-token", argument(0, "key"))
            } else null
            "basic" -> if (valueArguments.size == 2 && receiver()?.text?.substringAfterLast('.') == "Credentials") {
                SecretArgument("password", argument(1, "password"))
            } else null
            "UsernamePasswordCredentials", "PasswordAuthentication" ->
                if (valueArguments.size == 2) SecretArgument("password", argument(1, "password")) else null
            "getConnection", "DriverManagerDataSource" ->
                if (valueArguments.size == 3) SecretArgument("password", argument(2, "password")) else null
            "setBasicAuth" -> if (valueArguments.size == 1) {
                SecretArgument("configuration-token", argument(0, "encodedCredentials"))
            } else {
                argument(1, "password")?.let { SecretArgument("password", it) }
            }
            "password", "setPassword" -> SecretArgument("password", argument(0, "password", "value"))
            "option" -> if (valueArguments.size == 2 && r2dbcPasswordOption(argument(0, "option"))) SecretArgument("password", argument(1, "value")) else null
            "header", "setHeader", "addHeader", "defaultHeader", "set", "add", "append" -> {
                val header = argument(0, "name", "headerName")
                val key = fold(header)?.value ?: headerConstant(header)
                val kind = key?.let { headerKind(it) ?: secretKind(it) ?: weakSecretKind(it, fold(argument(1, "value", "headerValue", "values"))?.value) } ?: return null
                SecretArgument(kind, argument(1, "value", "headerValue", "values"))
            }
            else -> null
        }
    }

    /** R2DBC: `ConnectionFactoryOptions.PASSWORD`, импортированный `PASSWORD`, `Option.valueOf("password")`. */
    private fun r2dbcPasswordOption(option: KtExpression?): Boolean {
        when (val node = option?.unwrap()) {
            is KtQualifiedExpression -> {
                val call = node.selectorExpression as? KtCallExpression
                if (call != null) return node.receiverExpression.text.substringAfterLast('.') == "Option" && call.name() == "valueOf" &&
                    fold(call.argument(0, "value"))?.value.equals("password", ignoreCase = true)
                return node.selectorExpression?.referenceName() == "PASSWORD" &&
                    node.receiverExpression.text.substringAfterLast('.') == "ConnectionFactoryOptions"
            }
            is KtNameReferenceExpression -> return node.getReferencedName() == "PASSWORD" &&
                importedName("PASSWORD")?.substringBeforeLast('.')?.substringAfterLast('.') == "ConnectionFactoryOptions"
            else -> return false
        }
    }

    private fun headerConstant(expression: KtExpression?): String? {
        return when (val reference = expression?.unwrap()) {
            is KtQualifiedExpression -> {
                val spelling = reference.receiverExpression.text
                val receiver = importedName(spelling) ?: spelling
                if (receiver.substringAfterLast('.') !in headerTypes) return null
                reference.selectorExpression?.referenceName()?.replace('_', '-')
            }
            is KtNameReferenceExpression -> {
                val name = importedName(reference.getReferencedName()) ?: return null
                if (name.substringBeforeLast('.').substringAfterLast('.') !in headerTypes) return null
                name.substringAfterLast('.').replace('_', '-')
            }
            else -> null
        }
    }

    private fun importedName(name: String): String? =
        file.importDirectives.firstNotNullOfOrNull { directive ->
            val imported = directive.importedFqName ?: return@firstNotNullOfOrNull null
            if (directive.isAllUnder || (directive.aliasName ?: imported.shortName().asString()) != name) {
                return@firstNotNullOfOrNull null
            }
            imported.asString()
        }

    private fun fold(expression: KtExpression?, depth: Int = 0): Folded? {
        if (depth == 0) remainingFoldSteps = maxFoldSteps
        if (depth >= maxFoldDepth || remainingFoldSteps-- <= 0) return null
        val node = expression?.unwrap() ?: return null
        val next = depth + 1
        return when (node) {
            is KtStringTemplateExpression -> foldTemplate(node, next)
            is KtConstantExpression -> node.text.takeIf { it.startsWith('\'') }?.let {
                val char = kotlinChar(it) ?: return null
                Folded(char, listOf(location(node)))
            }
            is KtNameReferenceExpression -> {
                lambdaBindings[node.getReferencedName()]?.let { return it }
                val property = propertyInScope(node, node.getReferencedName())
                    ?: return foldMutable(node, next)
                    ?: externalConstant(node.getReferencedName(), null, next)
                fold(property.initializer ?: getterExpression(property), next)?.through(property)
            }
            is KtBinaryExpression -> {
                if (node.operationToken != KtTokens.PLUS) return null
                val left = fold(node.left, next) ?: return null
                val right = fold(node.right, next) ?: return null
                foldParts(listOf(left, right), node, transformed = combinesFragments(left, right))
            }
            is KtQualifiedExpression -> {
                val call = node.selectorExpression as? KtCallExpression
                if (call != null) return foldCall(call, node.receiverExpression, next)
                val name = node.selectorExpression?.referenceName() ?: return null
                if (node.receiverExpression !is KtThisExpression) {
                    val local = qualifiedConstant(node.receiverExpression, name)
                    if (local == null) return externalConstant(name, node.receiverExpression.unwrap(), next)
                    return fold(local.initializer, next)?.through(local)
                }
                val property = propertyInScope(node, name, membersOnly = true) ?: return null
                fold(property.initializer ?: getterExpression(property), next)?.through(property)
            }
            is KtCallExpression -> foldCall(node, null, next)
            else -> null
        }
    }

    /**
     * `var t = "a"; t += "b"`: локальная var, у которой до использования есть только инициализатор и `+=`.
     * Возвращает null (и поиск идёт дальше), если переменная не такая или переприсваивается через `=`.
     */
    private fun foldMutable(use: KtNameReferenceExpression, depth: Int): Folded? {
        val name = use.getReferencedName()
        for (scope in generateSequence(use.parent) { it.parent }) {
            if (scope !is KtBlockExpression && scope !is KtClassBody && scope !is KtFile) continue
            val declaration = (if (scope is KtBlockExpression) scope.statements else (scope as? KtClassBody)?.declarations
                ?: (scope as KtFile).declarations).filterIsInstance<KtProperty>()
                .lastOrNull { it.name == name && it.isVar && !it.hasDelegate() && it.textOffset < use.textOffset } ?: continue
            val initial = fold(declaration.initializer, depth)?.through(declaration) ?: return null
            val updates = PsiTreeUtil.findChildrenOfType(scope, KtBinaryExpression::class.java).filter {
                it.left?.unwrap()?.let { left -> left is KtNameReferenceExpression && left.getReferencedName() == name } == true &&
                    it.textOffset > declaration.textOffset && it.textOffset < use.textOffset
            }.sortedBy { it.textOffset }
            if (updates.any { it.operationToken == KtTokens.EQ }) return null
            var result = initial
            for (update in updates) {
                if (update.operationToken != KtTokens.PLUSEQ) return null
                val part = fold(update.right, depth) ?: return null
                result = foldParts(listOf(result, part), update, transformed = true) ?: return null
            }
            return if (updates.isEmpty()) null else result
        }
        return null
    }

    private var lambdaBindings: Map<String, Folded> = emptyMap()

    /** Свёртка инициализатора константы, объявленной в этом файле, по запросу другого файла. */
    fun foldConstant(property: KtProperty, depth: Int, steps: Int): Folded? {
        remainingFoldSteps = steps
        return fold(property.initializer, depth)?.through(property)
    }

    /** Константа из другого файла проекта: по импорту, пакету или полному имени. */
    private fun externalConstant(name: String, receiver: KtExpression?, depth: Int): Folded? {
        val keys = mutableListOf<String>()
        val prefix = packageName.let { if (it.isEmpty()) "" else "$it." }
        if (receiver == null) {
            if (name in declaredNames) return null
            importedName(name)?.let(keys::add)
            keys += "$prefix$name"
            file.importDirectives.filter { it.isAllUnder }.forEach { keys += "${it.importedFqName?.asString()}.$name" }
        } else {
            val spelling = receiver.text
            if (receiver is KtNameReferenceExpression) {
                if (spelling in declaredNames) return null
                importedName(spelling)?.let { keys += "$it.$name" }
                keys += "$prefix$spelling.$name"
                file.importDirectives.filter { it.isAllUnder }.forEach { keys += "${it.importedFqName?.asString()}.$spelling.$name" }
            } else if (receiver is KtQualifiedExpression) {
                keys += "$spelling.$name"
            }
        }
        val entry = keys.firstNotNullOfOrNull { table[it] } ?: return null
        if (entry.scanner === this) return null
        return entry.scanner.foldConstant(entry.property, depth, remainingFoldSteps.coerceAtLeast(1))
    }

    private fun foldTemplate(template: KtStringTemplateExpression, depth: Int): Folded? {
        var interpolations = 0
        val parts = template.entries.map { entry ->
            when (entry) {
                is KtLiteralStringTemplateEntry -> Folded(entry.text, emptyList())
                is KtEscapeStringTemplateEntry -> Folded(entry.unescapedValue, emptyList())
                else -> {
                    val part = fold(entry.expression, depth) ?: return null
                    if (entry.expression !is KtConstantExpression || part.value != "$") interpolations++
                    part
                }
            }
        }
        val contentParts = parts.count { it.value.isNotEmpty() }
        val bearerPrefix = parts.firstOrNull()?.value?.isBearerPrefix() == true
        return foldParts(parts, template, interpolations > 0 && contentParts > if (bearerPrefix) 2 else 1)
    }

    private fun qualifiedConstant(receiver: KtExpression, name: String): KtProperty? {
        val qualifier = receiver.unwrap() as? KtNameReferenceExpression ?: return null
        val qualifierName = qualifier.getReferencedName()
        if (propertyInScope(qualifier, qualifierName) != null) return null
        val type = file.declarations.filterIsInstance<KtClassOrObject>().singleOrNull { it.name == qualifierName }
        val owner = when (type) {
            is KtObjectDeclaration -> type
            is KtClass -> type.companionObjects.singleOrNull()
            else -> null
        } ?: return null
        return owner.declarations.filterIsInstance<KtProperty>().singleOrNull {
            it.name == name && it.hasModifier(KtTokens.CONST_KEYWORD)
        }
    }

    /** Единственная функция без параметров с таким именем в этом файле (`private fun carrierKey() = "…"`). */
    private fun fileFunction(name: String?): KtNamedFunction? {
        if (name == null) return null
        return children<KtNamedFunction>().filter { it.name == name && it.valueParameters.isEmpty() && it.receiverTypeReference == null }
            .singleOrNull()
    }

    private fun foldCall(call: KtCallExpression, receiver: KtExpression?, depth: Int): Folded? {
        if (call.valueArguments.isEmpty() && call.lambdaArguments.isEmpty() && call.name() !in builtinNames) {
            if (receiver == null) {
                fileFunction(call.name())?.let { function -> return fold(functionResult(function), depth)?.through(function) }
                foldTopLevelFunction(call.name(), depth)?.let { return it }
            } else {
                foldMemberFunction(call, receiver, depth)?.let { return it }
            }
        }
        if (receiver != null && call.lambdaArguments.isEmpty() &&
            (call.name() == "decodeToString" && call.valueArguments.isEmpty() || call.name() == "toString" && call.valueArguments.size == 1)) {
            foldCodes(receiver, depth)?.let { return codesFolded(it, call) }
        }
        when (call.name()) {
            "buildString" -> return if (receiver == null) foldBuilder(call, depth) else null
            "joinToString", "concatToString" -> return foldJoin(call, receiver, depth)
            "decode" -> return foldBase64(call, receiver, depth)
            "String" -> {
                if (receiver != null || call.valueArguments.size !in 1..2) return null
                val argument = call.argument(0, "bytes", "chars")
                val charsetName = call.argument(1, "charset")?.text?.substringAfterLast('.')
                if (charsetName == null || charsetName == "UTF_8" || charsetName == "US_ASCII" || charsetName == "ISO_8859_1") {
                    foldCodes(argument, depth)?.let { return codesFolded(it, call) }
                }
                val chars = foldCollection(argument, depth)
                if (chars != null && call.valueArguments.size == 1) return foldParts(chars, call, transformed = true)
                val charset = call.argument(1, "charset")
                if (charset != null && charset.text.substringAfterLast('.') != "UTF_8") return null
                return fold(argument, depth)?.takeIf { it.transformed }?.through(call)
            }
        }
        if (call.name() == "format" || call.name() == "formatted") foldFormat(call, receiver, depth)?.let { return it }
        if (call.name() == "toString" && call.valueArguments.isEmpty() && receiver != null) {
            builderParts(receiver, depth)?.let { parts -> return foldParts(parts, call, transformed = parts.size > 1) }
        }
        if ((call.name() == "fold" || call.name() == "reduce") && receiver != null) return foldReduce(call, receiver, depth)
        val previous = fold(receiver, depth) ?: return null
        if (call.name() == "replace" && call.valueArguments.size == 2 && call.lambdaArguments.isEmpty()) {
            val from = fold(call.argument(0, "oldValue"), depth) ?: return null
            val to = fold(call.argument(1, "newValue"), depth) ?: return null
            if (from.value.isEmpty()) return null
            return previous.copy(value = previous.value.replace(from.value, to.value), transformed = true).through(call)
        }
        if (call.name() == "plus") {
            val extra = fold(call.argument(0, "other"), depth) ?: return null
            return foldParts(listOf(previous, extra), call, transformed = combinesFragments(previous, extra))
        }
        if (call.name() in passThroughConversions) return previous.through(call)
        if (call.valueArguments.isNotEmpty()) return null
        val value = when (call.name()) {
            "uppercase", "toUpperCase" -> previous.value.uppercase()
            "lowercase", "toLowerCase" -> previous.value.lowercase()
            "reversed" -> previous.value.reversed()
            "trimIndent" -> previous.value.trimIndent()
            "trimMargin" -> previous.value.trimMargin()
            "trim" -> previous.value.trim()
            "decodeToString" -> previous.value.takeIf { previous.transformed } ?: return null
            else -> return null
        }
        return previous.copy(
            value = value,
            transformed = previous.transformed || call.name() in setOf("reversed", "uppercase", "toUpperCase", "lowercase", "toLowerCase"),
        ).through(call)
    }

    private fun functionResult(function: KtNamedFunction): KtExpression? {
        val body = function.bodyExpression ?: return null
        if (body !is KtBlockExpression) return body
        return (body.statements.lastOrNull() as? org.jetbrains.kotlin.psi.KtReturnExpression)?.returnedExpression
    }

    /** Свёртка тела функции, объявленной в этом файле, по запросу другого файла. */
    fun foldFunction(function: KtNamedFunction, depth: Int, steps: Int): Folded? {
        remainingFoldSteps = steps
        return fold(functionResult(function), depth)?.through(function)
    }

    /** `fun partner() = "a" + "b"` на верхнем уровне другого файла проекта: по импорту или пакету. */
    private fun foldTopLevelFunction(name: String?, depth: Int): Folded? {
        if (name == null || name in declaredNames) return null
        val prefix = packageName.let { if (it.isEmpty()) "" else "$it." }
        val keys = listOfNotNull(importedName(name), "$prefix$name") +
            file.importDirectives.filter { it.isAllUnder }.map { "${it.importedFqName?.asString()}.$name" }
        val entry = keys.firstNotNullOfOrNull { table.function(it) } ?: return null
        if (entry.scanner === this || entry.function.parent !is KtFile) return null
        return entry.scanner.foldFunction(entry.function, depth, remainingFoldSteps.coerceAtLeast(1))
    }

    /** `Tokens.partner()`, `Tokens().partner()`, `val t = Tokens(); t.partner()`: функция без параметров, возвращающая склеенный литерал. */
    private fun foldMemberFunction(call: KtCallExpression, receiver: KtExpression, depth: Int): Folded? {
        val name = call.name() ?: return null
        val prefix = packageName.let { if (it.isEmpty()) "" else "$it." }
        fun typeKeys(spelling: String): List<String> =
            listOfNotNull(importedName(spelling), "$prefix$spelling") +
                file.importDirectives.filter { it.isAllUnder }.map { "${it.importedFqName?.asString()}.$spelling" }
        val owners = when (val node = receiver.unwrap()) {
            is KtNameReferenceExpression -> {
                val spelling = node.getReferencedName()
                val property = propertyInScope(node, spelling)
                if (property != null) {
                    (property.initializer?.unwrap() as? KtCallExpression)?.takeIf { it.receiver() == null }?.name()?.let(::typeKeys).orEmpty()
                } else if (spelling in declaredNames) emptyList() else typeKeys(spelling)
            }
            is KtCallExpression -> if (node.receiver() == null) node.name()?.let(::typeKeys).orEmpty() else emptyList()
            is KtQualifiedExpression -> {
                val text = node.text.removeSuffix(".Companion")
                listOf(text) + typeKeys(text)
            }
            else -> emptyList()
        }
        val entry = owners.firstNotNullOfOrNull { table.function("$it.$name") } ?: return null
        return if (entry.scanner === this) {
            fold(functionResult(entry.function), depth)?.through(entry.function)
        } else {
            entry.scanner.foldFunction(entry.function, depth, remainingFoldSteps.coerceAtLeast(1))
        }
    }

    private class Codes(val values: List<Int>, val evidence: List<Location>)

    private fun intConstant(expression: KtExpression?): Int? {
        val text = expression?.unwrap()?.text?.replace(" ", "") ?: return null
        val charCode = Regex("^'(.|\\\\u[0-9a-fA-F]{4})'\\.code$").matchEntire(text)
        if (charCode != null) return kotlinChar("'${charCode.groupValues[1]}'")?.singleOrNull()?.code
        val number = Regex("^(-?)(0[xX][0-9a-fA-F_]+|0[bB][01_]+|\\d[\\d_]*)[uUlL]*(?:\\.to(?:Byte|Int|Short|Char|UByte|Long)\\(\\))*$").matchEntire(text) ?: return null
        val digits = number.groupValues[2].replace("_", "")
        val parsed = when {
            digits.startsWith("0x", true) -> digits.substring(2).toIntOrNull(16)
            digits.startsWith("0b", true) -> digits.substring(2).toIntOrNull(2)
            else -> digits.toIntOrNull()
        } ?: return null
        return if (number.groupValues[1] == "-") -parsed else parsed
    }

    /** `byteArrayOf(112, 107, …)`, `intArrayOf(…)`, `listOf(0x70, …)` или ссылка на такую константу: коды символов. */
    private fun foldCodes(expression: KtExpression?, depth: Int): Codes? {
        if (depth >= maxFoldDepth) return null
        val value = expression?.unwrap() ?: return null
        if (value is KtNameReferenceExpression) {
            val property = propertyInScope(value, value.getReferencedName()) ?: return null
            val inner = foldCodes(property.initializer ?: lazyBody(property), depth + 1) ?: return null
            return Codes(inner.values, inner.evidence + location(property))
        }
        val call = value as? KtCallExpression ?: return null
        if (call.name() !in codeFactories) return null
        val values = call.valueArguments.map { argument ->
            if (argument.getSpreadElement() != null) return null
            intConstant(argument.getArgumentExpression()) ?: return null
        }
        return Codes(values, listOf(location(call)))
    }

    private fun codeText(values: List<Int>): String? {
        if (values.isEmpty() || values.size > maxFoldLength) return null
        val text = when {
            values.all { it in 0..127 } -> String(CharArray(values.size) { values[it].toChar() })
            values.all { it in -128..255 } -> String(ByteArray(values.size) { values[it].toByte() }, Charsets.UTF_8)
            values.all { it in 0..0xFFFF } -> String(CharArray(values.size) { values[it].toChar() })
            else -> return null
        }
        return text.takeIf { t -> t.none { it.isISOControl() } }
    }

    private fun codesFolded(codes: Codes, site: KtElement): Folded? {
        val text = codeText(codes.values) ?: return null
        return Folded(text, (codes.evidence + location(site)).distinct(), transformed = true)
    }

    /** `intArrayOf(…).map { it.toChar() }`: коды превращаются в символы. */
    private fun foldCharMap(call: KtCallExpression, receiver: KtExpression, depth: Int): List<Folded>? {
        val lambda = call.lambdaArguments.singleOrNull()?.getLambdaExpression()
            ?: call.valueArguments.singleOrNull()?.getArgumentExpression() as? KtLambdaExpression
        if (lambda == null) {
            if (call.valueArguments.singleOrNull()?.getArgumentExpression()?.text?.replace(" ", "") != "Int::toChar") return null
        } else {
            if (lambda.valueParameters.size > 1) return null
            val parameter = Regex.escape(lambda.valueParameters.singleOrNull()?.name ?: "it")
            val body = lambda.bodyExpression?.statements?.singleOrNull()?.text?.replace(" ", "") ?: return null
            val allowed = Regex("^(?:Char\\($parameter(?:\\.toInt\\(\\))?\\)|\\(?$parameter(?:\\.toInt\\(\\)|\\.toUByte\\(\\)|\\.toUInt\\(\\))?\\)?\\.toChar\\(\\)(?:\\.toString\\(\\))?)$")
            if (!allowed.matches(body)) return null
        }
        val codes = foldCodes(receiver, depth + 1) ?: return null
        val evidence = (codes.evidence + location(call)).distinct()
        return codes.values.map { code -> Folded((if (code < 0) code + 256 else code).toChar().toString(), evidence) }
    }

    /** `listOf("a","b").fold("") { acc, s -> acc + s }` и `reduce`: подставляем элементы в тело лямбды. */
    private fun foldReduce(call: KtCallExpression, receiver: KtExpression, depth: Int): Folded? {
        val items = foldCollection(receiver, depth) ?: return null
        val lambda = (call.lambdaArguments.singleOrNull()?.getLambdaExpression()
            ?: call.valueArguments.lastOrNull()?.getArgumentExpression() as? KtLambdaExpression) ?: return null
        val names = lambda.valueParameters.map { it.name ?: return null }
        if (names.size != 2) return null
        val body = lambda.bodyExpression?.statements?.singleOrNull() ?: return null
        var accumulator: Folded
        val rest: List<Folded>
        if (call.name() == "fold") {
            accumulator = fold(call.valueArguments.firstOrNull()?.getArgumentExpression(), depth) ?: return null
            rest = items
        } else {
            if (items.isEmpty()) return null
            accumulator = items.first()
            rest = items.drop(1)
        }
        val saved = lambdaBindings
        try {
            for (item in rest) {
                lambdaBindings = saved + (names[0] to accumulator) + (names[1] to item)
                accumulator = fold(body, depth + 1) ?: return null
            }
        } finally {
            lambdaBindings = saved
        }
        return accumulator.copy(transformed = true).through(call)
    }

    /** `"%s%s".format(a, b)`, `String.format("%s%s", a, b)`, `.formatted(a, b)`: только %s, %n$s и %%. */
    private fun foldFormat(call: KtCallExpression, receiver: KtExpression?, depth: Int): Folded? {
        val args = call.valueArguments
        if (args.any { it.getArgumentName() != null || it.getSpreadElement() != null } || call.lambdaArguments.isNotEmpty()) return null
        val staticFormat = call.name() == "format" && receiver?.text.let { it == "String" || it == "java.lang.String" }
        if (!staticFormat && receiver == null) return null
        val template = fold(if (staticFormat) args.firstOrNull()?.getArgumentExpression() else receiver, depth) ?: return null
        val values = args.drop(if (staticFormat) 1 else 0).map { fold(it.getArgumentExpression(), depth) ?: return null }
        val parts = mutableListOf<Folded>()
        val text = template.value
        var index = 0
        var next = 0
        while (index < text.length) {
            if (text[index] != '%') {
                val end = text.indexOf('%', index).let { if (it < 0) text.length else it }
                parts += Folded(text.substring(index, end), emptyList())
                index = end
                continue
            }
            val spec = formatSpec.find(text.substring(index)) ?: return null
            if (spec.value == "%%") {
                parts += Folded("%", emptyList())
            } else {
                val position = spec.groupValues[1].takeIf { it.isNotEmpty() }?.toInt()?.minus(1) ?: next++
                parts += values.getOrNull(position) ?: return null
            }
            index += spec.value.length
        }
        val evidence = (template.evidence + parts.flatMap { it.evidence } + location(call)).distinct()
        val value = parts.joinToString("") { it.value }
        if (value.length > maxFoldLength) return null
        return Folded(value, evidence, transformed = true)
    }

    /** Части цепочки `StringBuilder(init).append(..).append(..)`, в том числе через val. */
    private fun builderParts(expression: KtExpression, depth: Int): List<Folded>? {
        if (depth >= maxFoldDepth) return null
        val node = expression.unwrap() ?: return null
        return when (node) {
            is KtNameReferenceExpression -> {
                val property = propertyInScope(node, node.getReferencedName()) ?: return null
                val initial = builderParts(property.initializer ?: return null, depth + 1)?.map { it.through(property) } ?: return null
                initial + (followingAppends(property, node, depth + 1) ?: return null)
            }
            is KtCallExpression -> {
                if (node.name() !in builderTypes || node.lambdaArguments.isNotEmpty() || node.valueArguments.size > 1) return null
                val init = node.valueArguments.firstOrNull()?.getArgumentExpression() ?: return emptyList()
                listOf(fold(init, depth + 1) ?: return null)
            }
            is KtQualifiedExpression -> {
                val call = node.selectorExpression as? KtCallExpression ?: return null
                if (call.name() == "apply" || call.name() == "also") {
                    val lambda = call.lambdaArguments.singleOrNull()?.getLambdaExpression() ?: return null
                    val start = builderParts(node.receiverExpression, depth + 1) ?: return null
                    return start + (lambda.bodyExpression?.statements ?: return null).flatMap { appendParts(it, depth + 1) ?: return null }
                }
                if (call.name() != "append" || call.valueArguments.size != 1) return null
                val before = builderParts(node.receiverExpression, depth + 1) ?: return null
                before + (fold(call.argument(0, "value"), depth + 1) ?: return null)
            }
            else -> null
        }
    }

    /**
     * Функция в классе/объекте или с именем про токен (`SisSyncToken.value()`), которая возвращает склеенное из констант
     * значение: секрет собран из кусков, хотя синк не виден.
     */
    private fun checkReturnedToken(function: KtNamedFunction) {
        val owner = PsiTreeUtil.getParentOfType(function, KtClassOrObject::class.java)
        val strongName = function.name?.let(::secretKind) != null || owner?.name?.let(::secretKind) != null
        val weakName = !strongName && (function.name?.let(::weakSecretName) != null || owner?.name?.let(::weakSecretName) != null)
        if (!strongName && !weakName) return
        val returned = if (function.hasBlockBody()) {
            PsiTreeUtil.findChildrenOfType(function, org.jetbrains.kotlin.psi.KtReturnExpression::class.java)
                .filter { PsiTreeUtil.getParentOfType(it, KtNamedFunction::class.java) == function }
                .mapNotNull { it.returnedExpression }
        } else {
            listOfNotNull(function.bodyExpression)
        }
        for (expression in returned) {
            val value = fold(expression) ?: continue
            val credential = value.value
            if (!value.transformed || credential.length < 8 || credential.any(Char::isWhitespace) || isPlaceholder(credential)) continue
            if (credential.none(Char::isDigit) || credential.none(Char::isLetter)) continue
            if (weakName && !looksLikeSecretValue(credential, 10)) continue
            val first = value.evidence.filter { it.path == source.path }
            if (first.isEmpty()) continue
            val end = first.maxOf { it.endLine ?: it.line }
            val primary = Location(source.path, first.minOf { it.line }, end)
            record("recoverable-token", credential, primary, value.evidence)
        }
    }

    /** `props.jwtSecret`: чтение секретного свойства класса настроек (@ConfigurationProperties, *Properties, *Config). */
    private fun configHolderRead(read: KtQualifiedExpression): Boolean {
        val name = (read.selectorExpression as? KtNameReferenceExpression)?.getReferencedName() ?: return false
        if (secretKind(name) == null) return false
        val holder = read.receiverExpression.unwrap() as? KtNameReferenceExpression ?: return false
        val holderName = holder.getReferencedName()
        val type = (children<KtParameter>().firstOrNull { it.name == holderName }?.typeReference
            ?: children<KtProperty>().firstOrNull { it.name == holderName }?.typeReference)
            ?.text?.substringAfterLast('.')?.substringBefore('<')
        if (type != null) return configHolderSuffixes.any { type.endsWith(it) }
        return holderName.lowercase() in setOf("props", "properties", "config", "settings", "configuration")
    }

    /** Продолжение `val sb = StringBuilder()`: отдельные операторы `sb.append(..).append(..)` до использования. */
    private fun followingAppends(property: KtProperty, use: KtNameReferenceExpression, depth: Int): List<Folded>? {
        val block = property.parent as? KtBlockExpression ?: return emptyList()
        val name = property.name ?: return emptyList()
        val parts = mutableListOf<Folded>()
        for (statement in block.statements) {
            if (statement.textOffset <= property.textOffset || statement.textOffset >= use.textOffset) continue
            if (PsiTreeUtil.isAncestor(statement, use, false)) continue
            val mentions = (statement as? KtNameReferenceExpression)?.getReferencedName() == name ||
                PsiTreeUtil.findChildrenOfType(statement, KtNameReferenceExpression::class.java).any { it.getReferencedName() == name }
            if (!mentions) continue
            val arguments = appendChainArguments(statement, name) ?: return null
            for (argument in arguments) parts += fold(argument, depth + 1) ?: return null
        }
        return parts.map { it.through(property) }
    }

    private fun appendChainArguments(statement: KtExpression, name: String): List<KtExpression>? {
        val arguments = ArrayDeque<KtExpression>()
        var current: KtExpression = statement.unwrap() ?: return null
        while (true) {
            if (current is KtNameReferenceExpression) return if (current.getReferencedName() == name) arguments else null
            val qualified = current as? KtQualifiedExpression ?: return null
            val call = qualified.selectorExpression as? KtCallExpression ?: return null
            if (call.name() != "append" || call.valueArguments.size != 1) return null
            arguments.addFirst(call.argument(0, "value") ?: return null)
            current = qualified.receiverExpression.unwrap() ?: return null
        }
    }

    private fun foldBuilder(call: KtCallExpression, depth: Int): Folded? {
        val lambda = call.lambdaArguments.singleOrNull()?.getLambdaExpression()
            ?: call.argument(0, "builderAction") as? KtLambdaExpression
        val statements = lambda?.bodyExpression?.statements ?: return null
        val parts = statements.flatMap { expression ->
            appendParts(expression, depth) ?: return null
        }
        return foldParts(parts, call, transformed = parts.size > 1)
    }

    private fun appendParts(expression: KtExpression, depth: Int): List<Folded>? {
        if (depth >= maxFoldDepth) return null
        val call = when (expression) {
            is KtCallExpression -> expression
            is KtQualifiedExpression -> expression.selectorExpression as? KtCallExpression ?: return null
            else -> return null
        }
        if (call.name() == "repeat" && call.receiver() == null) {
            val count = call.valueArgumentList?.arguments?.singleOrNull()?.getArgumentExpression()?.text?.toIntOrNull() ?: return null
            if (count !in 0..64) return null
            val body = call.lambdaArguments.singleOrNull()?.getLambdaExpression()?.bodyExpression?.statements ?: return null
            val once = body.flatMap { appendParts(it, depth + 1) ?: return null }
            return (1..count).flatMap { once }
        }
        val line = call.name() == "appendLine"
        if (call.name() != "append" && !line) return null
        if (call.valueArguments.size > 1 || (!line && call.valueArguments.isEmpty())) return null
        val own = listOfNotNull(
            call.valueArguments.firstOrNull()?.let { fold(call.argument(0, "value"), depth + 1) ?: return null },
            if (line) Folded("\n", emptyList()) else null,
        )
        val receiver = call.receiver()
        if (receiver == null || receiver is KtThisExpression) return own
        return appendParts(receiver, depth + 1)?.plus(own)
    }

    private fun foldJoin(call: KtCallExpression, receiver: KtExpression?, depth: Int): Folded? {
        val parts = foldCollection(receiver, depth) ?: return null
        if (call.name() == "concatToString") {
            if (call.valueArguments.isNotEmpty()) return null
            return foldParts(parts, call, transformed = parts.size > 1)
        }
        if (call.lambdaArguments.isNotEmpty() || call.valueArguments.any { argument ->
                val name = argument.getArgumentName()?.asName?.asString()
                name != null && name !in joinArgumentNames
            } || call.valueArguments.size > joinArgumentNames.size) return null
        fun argument(index: Int, name: String, default: String): Folded? {
            val value = call.argument(index, name) ?: return Folded(default, emptyList())
            return fold(value, depth)
        }
        val separator = argument(0, "separator", ", ") ?: return null
        val prefix = argument(1, "prefix", "") ?: return null
        val postfix = argument(2, "postfix", "") ?: return null
        val joined = buildList {
            add(prefix)
            for ((index, part) in parts.withIndex()) {
                if (index > 0) add(separator)
                add(part)
            }
            add(postfix)
        }
        return foldParts(joined, call, transformed = parts.size > 1 || prefix.value.isNotEmpty() || postfix.value.isNotEmpty())
    }

    private fun foldCollection(expression: KtExpression?, depth: Int): List<Folded>? {
        if (depth >= maxFoldDepth) return null
        val value = expression?.unwrap() ?: return null
        if (value is KtNameReferenceExpression) {
            val property = propertyInScope(value, value.getReferencedName()) ?: return null
            return foldCollection(property.initializer ?: lazyBody(property), depth + 1)?.map { it.through(property) }
        }
        if (value is KtQualifiedExpression) {
            val applied = value.selectorExpression as? KtCallExpression ?: return null
            if (applied.name() == "map") return foldCharMap(applied, value.receiverExpression, depth + 1)
            if (applied.name() != "apply" && applied.name() != "also") return null
            val base = foldCollection(value.receiverExpression, depth + 1) ?: return null
            val lambda = applied.lambdaArguments.singleOrNull()?.getLambdaExpression() ?: return null
            val added = (lambda.bodyExpression?.statements ?: return null).map { statement ->
                val add = (statement as? KtCallExpression
                    ?: (statement as? KtQualifiedExpression)?.takeIf { it.receiverExpression is KtThisExpression }?.selectorExpression as? KtCallExpression)
                    ?: return null
                if (add.name() != "add" || add.valueArguments.size != 1) return null
                fold(add.argument(0, "element"), depth + 1) ?: return null
            }
            return base + added
        }
        val call = value as? KtCallExpression ?: return null
        if (call.name() !in collectionFactories) return null
        return call.valueArguments.map { argument ->
            if (argument.getSpreadElement() != null) return null
            fold(argument.getArgumentExpression(), depth + 1) ?: return null
        }
    }

    private fun foldBase64(call: KtCallExpression, receiver: KtExpression?, depth: Int): Folded? {
        if (call.valueArguments.size != 1) return null
        val decoder = receiver as? KtQualifiedExpression
        val factory = decoder?.selectorExpression as? KtCallExpression
        val codec = if (decoder != null && factory != null) {
            val spelling = decoder.receiverExpression.text
            if ((importedName(spelling) ?: spelling) !in base64Qualifiers) return null
            when (factory.name()) {
                "getDecoder" -> Base64.getDecoder()
                "getUrlDecoder" -> Base64.getUrlDecoder()
                "getMimeDecoder" -> Base64.getMimeDecoder()
                else -> return null
            }
        } else {
            val spelling = receiver?.text ?: return null
            if ((importedName(spelling) ?: spelling) != "kotlin.io.encoding.Base64") return null
            Base64.getDecoder()
        }
        val input = fold(call.argument(0, "src", "source"), depth) ?: return null
        val value = try {
            codec.decode(input.value).decodeToString(throwOnInvalidSequence = true)
        } catch (_: IllegalArgumentException) {
            return null
        } catch (_: java.nio.charset.CharacterCodingException) {
            return null
        }
        return input.copy(value = value, transformed = true).through(call)
    }

    private fun foldParts(parts: List<Folded>, site: KtElement, transformed: Boolean): Folded? {
        if (parts.sumOf { it.value.length.toLong() } > maxFoldLength) return null
        return Folded(
            parts.joinToString("") { it.value },
            (parts.flatMap { it.evidence } + location(site)).distinct(),
            transformed || parts.any { it.transformed },
        )
    }

    private fun Folded.through(node: KtElement): Folded = copy(evidence = (evidence + location(node)).distinct())

    private fun location(element: PsiElement): Location {
        val range = element.textRange
        val start = source.lineAt(range.startOffset)
        val end = source.lineAt((range.endOffset - 1).coerceAtLeast(range.startOffset))
        return Location(source.path, start, end.takeIf { it > start })
    }

    private inline fun <reified T : KtElement> children(): Collection<T> = PsiTreeUtil.findChildrenOfType(file, T::class.java)
}

private class SecretArgument(val kind: String, val value: KtExpression?)
private class Folded(val value: String, val evidence: List<Location>, val transformed: Boolean = false) {
    fun copy(value: String = this.value, evidence: List<Location> = this.evidence, transformed: Boolean = this.transformed) =
        Folded(value, evidence, transformed)
}

private val directSecretKinds = setOf("password", "api-key", "configuration-token")
private val headerTypes = setOf("HttpHeaders", "HttpHeaderNames", "Headers")
private val collectionFactories = setOf("arrayOf", "listOf", "charArrayOf", "mutableListOf", "arrayListOf", "ArrayList")
private val codeFactories = setOf("byteArrayOf", "intArrayOf", "shortArrayOf", "listOf", "arrayOf", "ubyteArrayOf", "uintArrayOf")
private val passThroughConversions = setOf("toCharArray", "toByteArray", "encodeToByteArray", "toString", "toCharSequence")
private val passThroughReads = setOf("takeUnless", "takeIf", "trim", "orEmpty", "trimIndent", "filter")
private val configHolderSuffixes = listOf("Properties", "Props", "Config", "Configuration", "Settings", "Secrets", "Credentials")
private val environmentWrapperNames = setOf("env", "getEnv", "envOrNull", "getenvOrNull", "envVar", "readEnv", "environmentVariable")
private val apiKeyScheme = Regex("^(?:Api-?Key|Key)\\s+\\S", RegexOption.IGNORE_CASE)
private val builtinNames = setOf("emptyList", "emptySet", "emptyMap", "mutableListOf", "listOf", "setOf", "mapOf", "arrayOf", "StringBuilder", "StringBuffer", "toString", "uppercase", "lowercase", "trim", "reversed")
private val builderTypes =setOf("StringBuilder", "StringBuffer")
private val formatSpec = Regex("^%(?:(\\d+)\\$)?s|^%%")
private val base64Qualifiers = setOf("Base64", "java.util.Base64")
private val joinArgumentNames = setOf("separator", "prefix", "postfix")
private val springPlaceholder = Regex("""\$\{([^}:]+)(?::([\s\S]*))?}""")
private const val maxFoldDepth = 24
private const val maxFoldSteps = 4_096
private const val maxFoldLength = 65_536

/** Тело лямбды `by lazy { … }`: последнее выражение, если делегат — `lazy`. */
private fun lazyBody(property: KtProperty): KtExpression? {
    val call = property.delegateExpression?.let { it as? KtCallExpression ?: (it as? KtQualifiedExpression)?.selectorExpression as? KtCallExpression }
        ?: return null
    if (call.name() != "lazy") return null
    val lambda = call.lambdaArguments.singleOrNull()?.getLambdaExpression()
        ?: call.valueArguments.lastOrNull()?.getArgumentExpression() as? KtLambdaExpression ?: return null
    return lambda.bodyExpression?.statements?.lastOrNull()
}

private val nonSecretHeaderWords = setOf("idempotency", "cache", "routing", "partition", "correlation", "trace", "request", "sort", "websocket", "forwarded")

/**
 * Класс секрета по имени HTTP-заголовка. [bare] = false отключает правила для имён без префикса `x-`
 * (так проверяется значение, которое может оказаться именем заголовка).
 */
internal fun headerKind(key: String, bare: Boolean = true): String? {
    val name = key.lowercase()
    val words = name.split('-')
    return when {
        name == "x-api-key" || name == "x-apikey" || (bare && (name == "api-key" || name == "apikey")) -> "api-key"
        name == "authorization" || name == "proxy-authorization" -> "configuration-token"
        words.any { it in nonSecretHeaderWords } -> null
        name.startsWith("x-") && name.endsWith("-token") -> "configuration-token"
        name.startsWith("x-auth") -> "configuration-token"
        name.startsWith("x-") && name.endsWith("-secret") -> "configuration-token"
        bare && name.endsWith("-secret") -> "configuration-token"
        name.startsWith("x-") && words.size >= 3 && name.endsWith("-key") -> "api-key"
        bare && name == "ocp-apim-subscription-key" -> "api-key"
        else -> null
    }
}

private fun bearerLiteral(value: String): String? {
    if (!value.startsWith("Bearer ", ignoreCase = true)) return null
    val rest = value.substring("Bearer ".length).trim()
    return rest.takeIf { it.length >= 6 && ' ' !in it && '$' !in it && '{' !in it && !isPlaceholder(it) }
}

private fun String.withoutBearer(): String = when {
    startsWith("Bearer ", ignoreCase = true) -> substring("Bearer ".length).trim()
    apiKeyScheme.containsMatchIn(this) -> substringAfter(' ').trim()
    startsWith("{noop}") -> substring("{noop}".length)
    else -> this
}

private val encodedPassword = Regex("""^(?:\{(?:bcrypt|pbkdf2|scrypt|argon2|sha256|sha1|md5|ldap)}.*|\$2[abxy]\$\d\d\$.{50,})$""", RegexOption.IGNORE_CASE)

private fun String.isBearerPrefix(): Boolean =
    trim().let { it.equals("Bearer", ignoreCase = true) || it.equals("Key", ignoreCase = true) || it.equals("ApiKey", ignoreCase = true) || it.equals("Api-Key", ignoreCase = true) } &&
        lastOrNull()?.isWhitespace() == true

private fun combinesFragments(left: Folded, right: Folded): Boolean =
    left.value.isNotEmpty() && right.value.isNotEmpty() && !left.value.isBearerPrefix()

private fun kotlinChar(spelling: String): String? {
    val content = spelling.removeSurrounding("'")
    if (content.length == 1) return content
    return when (content) {
        "\\t" -> "\t"
        "\\b" -> "\b"
        "\\n" -> "\n"
        "\\r" -> "\r"
        "\\'" -> "'"
        "\\\"" -> "\""
        "\\\\" -> "\\"
        "\\$" -> "$"
        else -> content.takeIf { it.startsWith("\\u") && it.length == 6 }?.drop(2)?.toIntOrNull(16)?.toChar()?.toString()
    }
}

private fun KtCallExpression.name(): String? = (calleeExpression as? KtNameReferenceExpression)?.getReferencedName()

private fun KtCallExpression.receiver(): KtExpression? =
    (parent as? KtQualifiedExpression)?.takeIf { it.selectorExpression == this }?.receiverExpression

private fun KtCallElement.argument(index: Int, vararg names: String): KtExpression? =
    valueArguments.firstOrNull { it.getArgumentName()?.asName?.asString() in names }?.getArgumentExpression()
        ?: valueArguments.getOrNull(index)?.takeIf { it.getArgumentName() == null }?.getArgumentExpression()

private tailrec fun KtExpression.unwrap(): KtExpression? =
    if (this is KtParenthesizedExpression) expression?.unwrap() else this

private fun KtExpression.referenceName(): String? = when (val value = unwrap()) {
    is KtNameReferenceExpression -> value.getReferencedName()
    is KtQualifiedExpression -> (value.selectorExpression as? KtNameReferenceExpression)?.getReferencedName()
    else -> null
}

private fun propertyInScope(use: KtElement, name: String, membersOnly: Boolean = false): KtProperty? {
    for (scope in generateSequence(use.parent) { it.parent }) {
        val declarations = when (scope) {
            is KtBlockExpression -> if (membersOnly) emptyList() else scope.statements.filter { it.textOffset < use.textOffset }
            is KtClassBody -> scope.declarations
            is KtFile -> if (membersOnly) return null else scope.declarations
            is KtDeclarationWithBody -> {
                if (!membersOnly && scope.valueParameters.any { it.name == name }) return null
                emptyList()
            }
            is KtClass -> {
                if (scope.primaryConstructorParameters.any { it.name == name }) return null
                val companion = scope.companionObjects.singleOrNull()
                companion?.declarations.orEmpty()
            }
            else -> continue
        }
        val property = declarations.filterIsInstance<KtProperty>().lastOrNull {
            it.name == name && !PsiTreeUtil.isAncestor(it, use, false)
        } ?: continue
        return property.takeUnless { it.isVar || (it.hasDelegate() && lazyBody(it) == null) }
    }
    return null
}
