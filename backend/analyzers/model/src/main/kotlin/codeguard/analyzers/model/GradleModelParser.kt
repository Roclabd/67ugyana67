package codeguard.analyzers.model

import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtArrayAccessExpression
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBinaryExpressionWithTypeRHS
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtObjectDeclaration
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtQualifiedExpression
import org.jetbrains.kotlin.psi.KtScriptInitializer
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.tomlj.Toml
import org.tomlj.TomlArray
import org.tomlj.TomlParseResult
import org.tomlj.TomlTable
import java.util.Properties

data class GradleModel(
    val dependencies: List<DeclaredDependency>,
    val properties: Map<String, Located<String>>,
    val lockfile: Map<String, String>,
)

data class DeclaredDependency(
    val configuration: String,
    val group: String,
    val artifact: String,
    val declaredVersion: String?,
    val resolvedVersion: String?,
    val unresolvedReason: String?,
    val resolution: List<Location>,
    val declaredAt: Location,
    val springBootBom: SpringBootBomUse? = null,
)

data class SpringBootBomUse(val release: String, val declaredAt: Location)

internal fun parseGradle(
    files: List<SourceFile>,
    kotlin: Map<String, KtFile>,
    catalogs: Map<String, TomlParseResult>,
    errors: MutableList<ParseError>,
): GradleModel {
    val sources = files.associateBy { it.path }
    val properties = files.filter { it.path.substringAfterLast('/') == "gradle.properties" }
        .associate { it.path to readGradleProperties(it, errors) }
    val locks = files.filter { it.path.substringAfterLast('/') == "gradle.lockfile" }
        .associate { it.path to readGradleLockfile(it, errors) }
    val buildConstants = buildSrcConstants(sources, kotlin)
    val gradleCatalogs = catalogs.mapValues { (path, table) -> TomlGradleCatalog(path, table) }
    val settingsCatalogs = kotlin.filterKeys { it.substringAfterLast('/') == "settings.gradle.kts" }
        .mapValues { (path, psi) -> SettingsGradleCatalog(sources.getValue(path), psi) }
    val modelProperties = linkedMapOf<String, Located<String>>()
    properties.values.forEach { entries -> entries.forEach { (key, value) -> modelProperties.putIfAbsent(key, value) } }
    val modelLocks = linkedMapOf<String, String>()
    locks.values.forEach { entries ->
        entries.forEach { (key, values) ->
            values.map { it.version }.distinct().singleOrNull()?.let { modelLocks.putIfAbsent(key, it) }
        }
    }

    val modules = kotlin.filterKeys { it.endsWith(".gradle.kts") }.mapValues { (path, psi) ->
        val source = sources.getValue(path)
        val directories = generateSequence(path.substringBeforeLast('/', "")) { directory ->
            directory.takeIf { it.isNotEmpty() }?.substringBeforeLast('/', "")
        }.toList()
        fun ancestors(name: String): List<String> = directories.map { directory ->
            if (directory.isEmpty()) name else "$directory/$name"
        }
        val gradleProperties = ancestors("gradle.properties").asReversed()
            .mapNotNull(properties::get).fold(emptyMap<String, Located<String>>()) { acc, local -> acc + local }
        val scopedLocks = ancestors("gradle.lockfile").firstNotNullOfOrNull(locks::get).orEmpty()
        val catalog = listOfNotNull(
            ancestors("gradle/libs.versions.toml").firstNotNullOfOrNull(gradleCatalogs::get),
            ancestors("settings.gradle.kts").firstNotNullOfOrNull(settingsCatalogs::get),
        ).takeIf(List<GradleCatalog>::isNotEmpty)?.let(::CompositeGradleCatalog)
        val constants = directories.firstNotNullOfOrNull(buildConstants::get).orEmpty()
        val script = GradleScript(source, psi, gradleProperties, constants)
        script.resolvedProperties().forEach { (key, value) -> modelProperties[key] = value }
        val settings = ancestors("settings.gradle.kts").zip(ancestors("settings.gradle"))
        val buildBoundary = settings.indexOfFirst { (kotlinSettings, groovySettings) ->
            kotlinSettings in sources || groovySettings in sources
        }
        val ancestorBuilds = ancestors("build.gradle.kts").drop(1)
            .let { if (buildBoundary >= 0) it.take(buildBoundary) else it }
        val declarations = script.dependencyDeclarations(catalog, errors)
        GradleModule(script, catalog, scopedLocks, declarations, script.platforms(declarations, catalog, scopedLocks), ancestorBuilds)
    }
    val sharedPlatforms = modules.mapValues { (_, module) ->
        module.platforms.filter { it.scope == GradleBomScope.SUBPROJECTS || it.scope == GradleBomScope.ALLPROJECTS }
            .map { it.copy(scope = GradleBomScope.NESTED) }
    }
    val dependencies = modules.values.flatMap { module ->
        val inheritedPlatforms = module.ancestorBuilds.flatMap { sharedPlatforms[it].orEmpty() }
        module.script.dependencies(module.declarations, module.catalog, module.lockfile, module.platforms + inheritedPlatforms)
    }
    return GradleModel(dependencies, modelProperties, modelLocks)
}

private fun readGradleProperties(source: SourceFile, errors: MutableList<ParseError>): Map<String, Located<String>> {
    val entries = linkedMapOf<String, Located<String>>()
    val lines = source.text.lineSequence().iterator()
    var lineNumber = 0
    while (lines.hasNext()) {
        var line = lines.next().removePrefix("\uFEFF")
        val start = ++lineNumber
        if (line.isBlank() || line.trimStart().startsWith('#') || line.trimStart().startsWith('!')) continue
        val record = StringBuilder(line)
        while (line.reversed().takeWhile { it == '\\' }.length % 2 == 1 && lines.hasNext()) {
            line = lines.next()
            lineNumber++
            record.append('\n').append(line)
        }
        try {
            val property = Properties().apply { load(record.toString().reader()) }
            for (name in property.stringPropertyNames()) {
                entries[name] = Located(property.getProperty(name), Location(source.path, start, lineNumber.takeIf { it != start }))
            }
        } catch (_: IllegalArgumentException) {
            errors += ParseError(source.path, start, "Некорректная escape-последовательность в gradle.properties")
        }
    }
    return entries
}

internal data class GradleLock(val version: String, val configurations: Set<String>, val location: Location) {
    fun hasUnknownScopeFor(configuration: String): Boolean =
        configuration !in knownGradleConfigurations || configurations.any { it !in knownGradleConfigurations }
}

internal data class GradleLockSelection(val applicable: List<GradleLock>, val unknown: List<GradleLock>) {
    val version: String? get() = applicable.map(GradleLock::version).distinct().singleOrNull()
    val evidence: List<Location> get() = (applicable + unknown).map(GradleLock::location)
}

internal fun selectGradleLocks(
    locks: List<GradleLock>,
    configuration: String,
    classpaths: Set<String> = jvmDeclarationClasspaths[configuration].orEmpty(),
): GradleLockSelection {
    val applicable = locks.filter { lock -> lock.configurations.any { it == configuration || it in classpaths } }
    val unknown = if (applicable.isEmpty()) locks.filter { it.hasUnknownScopeFor(configuration) } else emptyList()
    return GradleLockSelection(applicable, unknown)
}

private fun readGradleLockfile(source: SourceFile, errors: MutableList<ParseError>): Map<String, List<GradleLock>> {
    val entries = linkedMapOf<String, MutableList<GradleLock>>()
    source.text.lineSequence().forEachIndexed { index, line ->
        val record = line.removePrefix("\uFEFF").trim()
        if (record.isEmpty() || record.startsWith('#') || record.startsWith("empty=")) return@forEachIndexed
        val coordinate = record.substringBefore('=').split(':')
        val configurations = record.substringAfter('=', "").split(',').map(String::trim).toSet()
        if (coordinate.size != 3 || coordinate.any(String::isBlank) || "" in configurations) {
            errors += ParseError(source.path, index + 1, "Некорректная запись в gradle.lockfile")
            return@forEachIndexed
        }
        val (group, artifact, version) = coordinate
        entries.getOrPut("$group:$artifact", ::mutableListOf) +=
            GradleLock(version, configurations, Location(source.path, index + 1))
    }
    return entries
}

private data class GradleCoordinate(
    val group: String,
    val artifact: String,
    val declaredVersion: String?,
    val version: String?,
    val evidence: List<Location> = emptyList(),
    val unresolvedReason: String? = null,
    val versionOmitted: Boolean = declaredVersion == null && version == null,
    val declaredAt: Location? = null,
    val strict: Boolean = false,
)

internal fun isVersionCatalog(path: String): Boolean = path.substringAfterLast('/') == "libs.versions.toml"

internal fun parseVersionCatalogs(files: List<SourceFile>, errors: MutableList<ParseError>): Map<String, TomlParseResult> =
    files.filter { isVersionCatalog(it.path) }.associate { source ->
        val table = Toml.parse(source.text.removePrefix("\uFEFF"))
        table.errors().forEach { error ->
            errors += ParseError(source.path, error.position().line(), "Ошибка синтаксиса каталога версий")
        }
        source.path to table
    }

private interface GradleCatalog {
    fun lookup(reference: String): List<GradleCoordinate>
}

private class CompositeGradleCatalog(private val parts: List<GradleCatalog>) : GradleCatalog {
    override fun lookup(reference: String): List<GradleCoordinate> =
        parts.firstNotNullOfOrNull { it.lookup(reference).takeIf(List<GradleCoordinate>::isNotEmpty) }.orEmpty()
}

private class TomlGradleCatalog(private val path: String, private val table: TomlTable) : GradleCatalog {
    private val libraries = table.get("libraries") as? TomlTable
    private val aliases = libraries?.keySet()?.associateBy(::accessor).orEmpty()
    private val bundles = table.get("bundles") as? TomlTable
    private val bundleAliases = bundles?.keySet()?.associateBy(::accessor).orEmpty()

    override fun lookup(reference: String): List<GradleCoordinate> {
        if (!reference.startsWith("libs.")) return emptyList()
        val aliasPath = reference.removePrefix("libs.").removeSuffix(".get()")
        if (!aliasPath.startsWith("bundles.")) return listOfNotNull(aliases[aliasPath]?.let(::library))
        val key = bundleAliases[aliasPath.removePrefix("bundles.")] ?: return emptyList()
        val names = bundles?.get(listOf(key)) as? TomlArray ?: return emptyList()
        val location = bundles.inputPositionOf(listOf(key))?.let { Location(path, it.line()) }
        return (0 until names.size()).mapNotNull { index ->
            val coordinate = (names.get(index) as? String)?.let(::library) ?: return@mapNotNull null
            coordinate.copy(evidence = listOfNotNull(location) + coordinate.evidence)
        }
    }

    private fun library(alias: String): GradleCoordinate? {
        val entry = libraries?.get(listOf(alias)) ?: return null
        val location = libraries.inputPositionOf(listOf(alias))?.let { Location(path, it.line()) }
        if (entry is String) return coordinate(entry, entry, listOfNotNull(location))
        entry as? TomlTable ?: return null
        val module = entry.get("module") as? String
        val group = module?.substringBefore(':') ?: entry.get("group") as? String ?: return null
        val artifact = module?.substringAfter(':', "") ?: entry.get("name") as? String ?: return null
        if (!validCoordinatePart(group) || !validCoordinatePart(artifact)) return null
        val reference = entry.get("version.ref") as? String
        val version = if (reference == null) catalogVersion(entry.get("version")) else {
            catalogVersion(table.get(listOf("versions", reference)))
        }
        val referenceLocation = reference?.let { table.inputPositionOf(listOf("versions", it)) }
            ?.let { Location(path, it.line()) }
        return GradleCoordinate(group, artifact, reference ?: version, version, listOfNotNull(location, referenceLocation),
            reference?.takeIf { version == null }?.let { "Ссылка на версию в каталоге не разрешена" },
            versionOmitted = reference == null && entry.get("version") == null)
    }

    private fun accessor(alias: String): String = alias.replace('-', '.').replace('_', '.')

    private fun catalogVersion(value: Any?): String? = when (value) {
        is String -> value
        is TomlTable -> (value.get("strictly") ?: value.get("require")) as? String
        else -> null
    }
}

/** Version catalogs declared in settings.gradle.kts: versionCatalogs { create("libs") { library(...).version(...) } }. */
private class SettingsGradleCatalog(private val source: SourceFile, psi: KtFile) : GradleCatalog {
    private data class CatalogVersion(val value: String?, val location: Location)

    private val libraries = linkedMapOf<String, GradleCoordinate>()

    init {
        PsiTreeUtil.findChildrenOfType(psi, KtCallExpression::class.java)
            .filter { call ->
                call.calleeExpression?.text == "create" && call.lambdaArguments.isNotEmpty() &&
                    generateSequence(call.parent) { it.parent }.filterIsInstance<KtCallExpression>()
                        .any { it.calleeExpression?.text == "versionCatalogs" }
            }
            .sortedBy(KtCallExpression::getTextOffset)
            .forEach { create ->
                val name = stringLiteral(create.argument("name", 0)) ?: return@forEach
                read(name, create.lambdaStatements())
            }
    }

    override fun lookup(reference: String): List<GradleCoordinate> =
        listOfNotNull(libraries[reference.removeSuffix(".get()")])

    private fun read(catalog: String, statements: List<KtExpression>) {
        val versions = mutableMapOf<String, CatalogVersion>()
        val declarations = mutableListOf<Pair<KtExpression, List<KtCallExpression>>>()
        for (statement in statements) {
            val chain = callChain(statement)
            val head = chain.firstOrNull() ?: continue
            when (head.calleeExpression?.text) {
                "version" -> if (chain.size == 1) {
                    val name = stringLiteral(head.argument("name", 0)) ?: continue
                    versions[name] = CatalogVersion(versionValue(head, 1), source.location(statement.textOffset))
                }
                "library" -> declarations += statement to chain
            }
        }
        for ((statement, chain) in declarations) {
            val head = chain.first()
            val alias = stringLiteral(head.argument("alias", 0)) ?: continue
            val group: String?
            val artifact: String?
            var version: String? = null
            if (head.valueArguments.size >= 3) {
                group = stringLiteral(head.argument("group", 1))
                artifact = stringLiteral(head.argument("name", 2))
            } else {
                val parts = stringLiteral(head.argument("notation", 1))?.split(':').orEmpty()
                group = parts.getOrNull(0)
                artifact = parts.getOrNull(1)
                version = parts.getOrNull(2)
            }
            if (group == null || artifact == null || !validCoordinatePart(group) || !validCoordinatePart(artifact)) continue
            var declared = version
            var omitted = version == null
            var reason: String? = null
            val evidence = mutableListOf<Location>()
            for (modifier in chain.drop(1)) {
                when (modifier.calleeExpression?.text) {
                    "version" -> {
                        version = versionValue(modifier, 0)
                        declared = version
                        omitted = false
                        reason = if (version == null) "Не удалось определить версию каталога статически" else null
                    }
                    "versionRef" -> {
                        val reference = stringLiteral(modifier.argument("name", 0))
                        val target = reference?.let(versions::get)
                        declared = reference
                        version = target?.value
                        omitted = false
                        target?.let { evidence += it.location }
                        reason = if (version == null) "Ссылка на версию в каталоге не разрешена" else null
                    }
                    "withoutVersion" -> {
                        version = null
                        declared = null
                        omitted = true
                        reason = null
                    }
                }
            }
            libraries["$catalog.${alias.replace('-', '.').replace('_', '.')}"] = GradleCoordinate(
                group, artifact, declared, version, evidence, reason, omitted, source.location(statement.textOffset),
            )
        }
    }

    private fun versionValue(call: KtCallExpression, index: Int): String? {
        if (call.lambdaArguments.isEmpty()) return stringLiteral(call.argument("version", index))
        val constraints = call.lambdaStatements().mapNotNull { it.asGradleCall() }
        for (kind in listOf("strictly", "require", "prefer")) {
            constraints.firstOrNull { it.calleeExpression?.text == kind }
                ?.let { stringLiteral(it.argument("version", 0)) }?.let { return it }
        }
        return null
    }

    private fun callChain(expression: KtExpression): List<KtCallExpression> = when (expression) {
        is KtQualifiedExpression ->
            callChain(expression.receiverExpression) + listOfNotNull(expression.selectorExpression as? KtCallExpression)
        is KtCallExpression -> listOf(expression)
        else -> emptyList()
    }
}

private data class GradleValue(val text: String, val evidence: List<Location> = emptyList())

/** Resolve explicit string constants of the corresponding buildSrc without loading Gradle plugins. */
private fun buildSrcConstants(
    files: Map<String, SourceFile>, kotlin: Map<String, KtFile>,
): Map<String, Map<String, GradleValue>> {
    val candidates = mutableMapOf<String, MutableMap<String, MutableList<GradleValue>>>()
    val sourceRoot = Regex("""^(?:(.*)/)?buildSrc/src/main/kotlin/.+\.kt$""")
    for ((path, file) in kotlin) {
        val buildRoot = sourceRoot.matchEntire(path)?.groupValues?.get(1) ?: continue
        val values = candidates.getOrPut(buildRoot, ::mutableMapOf)
        val packageName = file.packageFqName.asString()
        for (declaration in file.declarations.filterIsInstance<KtObjectDeclaration>()) {
            val objectName = declaration.name ?: continue
            if (declaration.hasModifier(KtTokens.PRIVATE_KEYWORD)) continue
            for (property in declaration.declarations.filterIsInstance<KtProperty>()) {
                if (!property.hasModifier(KtTokens.CONST_KEYWORD) || property.hasModifier(KtTokens.PRIVATE_KEYWORD)) continue
                val name = property.name ?: continue
                val value = stringLiteral(property.initializer) ?: continue
                val qualified = listOf(packageName, objectName, name).filter(String::isNotEmpty).joinToString(".")
                val location = files.getValue(path).location(property.textOffset)
                values.getOrPut(qualified, ::mutableListOf).add(GradleValue(value, listOf(location)))
            }
        }
    }
    return candidates.mapValues { (_, entries) ->
        entries.mapNotNull { (name, values) -> values.singleOrNull()?.let { name to it } }.toMap()
    }
}

private data class GradleModule(
    val script: GradleScript,
    val catalog: GradleCatalog?,
    val lockfile: Map<String, List<GradleLock>>,
    val declarations: List<GradleDependencyCall>,
    val platforms: List<GradleBomImport>,
    val ancestorBuilds: List<String>,
)

private data class GradleDependencyCall(
    val configuration: String,
    val call: KtCallExpression,
    val coordinates: List<GradleCoordinate>,
    val platform: GradlePlatformKind?,
    val scope: GradleBomScope,
    val richVersion: Boolean,
    val constraint: Boolean = false,
)

private data class GradlePluginRequest(
    val id: String,
    val location: Location,
    val version: GradleValue? = null,
    val applied: Boolean = true,
)

private class GradleScript(
    private val source: SourceFile,
    private val psi: KtFile,
    private val gradleProperties: Map<String, Located<String>>,
    private val buildConstants: Map<String, GradleValue>,
) {
    private val statements = psi.script?.blockExpression?.statements.orEmpty()
    private val topLevelExpressions = statements.mapNotNull { statement ->
        (statement as? KtScriptInitializer)?.body ?: statement
    }
    private val topLevelCalls = topLevelExpressions.filterIsInstance<KtCallExpression>()
    private val calls = PsiTreeUtil.findChildrenOfType(psi, KtCallExpression::class.java)
    private val declarations = statements.filterIsInstance<KtProperty>().filterNot(KtProperty::isVar)
        .mapNotNull { property -> property.name?.let { it to property } }.toMap()
    private val imports = psi.importDirectives.filterNot { it.isAllUnder }
        .mapNotNull { directive ->
            val path = directive.importedFqName ?: return@mapNotNull null
            (directive.aliasName ?: path.shortName().asString()) to path.asString()
        }.toMap()
    private val extra: Map<String, Pair<KtExpression, KtExpression>> = statements.mapNotNull { statement ->
        val expression = (statement as? KtScriptInitializer)?.body ?: statement
        if (expression is KtQualifiedExpression) {
            val call = expression.selectorExpression as? KtCallExpression
            if (call?.calleeExpression?.text != "set" || !isExtra(expression.receiverExpression.text)) return@mapNotNull null
            val value = call.argument("value", 1) ?: return@mapNotNull null
            return@mapNotNull stringLiteral(call.argument("name", 0))?.let { it to (expression to value) }
        }
        val assignment = expression as? KtBinaryExpression ?: return@mapNotNull null
        val access = assignment.left as? KtArrayAccessExpression ?: return@mapNotNull null
        if (assignment.operationToken != KtTokens.EQ || !isExtra(access.arrayExpression?.text)) return@mapNotNull null
        val value = assignment.right ?: return@mapNotNull null
        stringLiteral(access.indexExpressions.singleOrNull())?.let { it to (assignment to value) }
    }.toMap()

    fun resolvedProperties(): Map<String, Located<String>> = buildMap {
        extra.forEach { (key, assignment) ->
            resolveExtra(key, emptySet())?.let { put(key, Located(it.text, source.location(assignment.first.textOffset))) }
        }
        declarations.forEach { (key, property) ->
            resolveDeclaration(key, emptySet())?.let { put(key, Located(it.text, source.location(property.textOffset))) }
        }
    }

    fun dependencyDeclarations(
        catalog: GradleCatalog?,
        errors: MutableList<ParseError>,
    ): List<GradleDependencyCall> = calls
        .filter { it.calleeExpression?.text == "dependencies" && it.lambdaArguments.isNotEmpty() }
        .sortedBy(KtCallExpression::getTextOffset)
        .flatMap { block ->
            val scope = dependencyScope(block)
            block.lambdaStatements().flatMap { statement ->
                val constraints = statement.asGradleCall()?.takeIf {
                    it.calleeExpression?.text == "constraints" && it.lambdaArguments.isNotEmpty()
                }
                if (constraints == null) {
                    listOfNotNull(readDependency(statement, scope, catalog, errors))
                } else {
                    constraints.lambdaStatements().mapNotNull {
                        readDependency(it, scope, catalog, errors)?.copy(constraint = true)
                    }
                }
            }
        }

    fun platforms(
        declarations: List<GradleDependencyCall>,
        catalog: GradleCatalog?,
        lockfile: Map<String, List<GradleLock>>,
    ): List<GradleBomImport> {
        val knownCalls = declarations.mapTo(hashSetOf(), GradleDependencyCall::call)
        val declared = declarations.filter { it.scope != GradleBomScope.BUILDSCRIPT }.mapNotNull { platformImport(it, lockfile) }
        val nested = calls.filterNot { it in knownCalls }.mapNotNull { possiblePlatformImport(it, catalog) }
        return (declared + nested).sortedBy { it.declaredAt.line }
    }

    private fun possiblePlatformImport(call: KtCallExpression, catalog: GradleCatalog?): GradleBomImport? {
        val name = call.calleeExpression?.text?.removeSurrounding("`") ?: return null
        val notation = call.argument("dependencyNotation", if (name == "add") 1 else 0)?.withoutParentheses() ?: return null
        val wrapper = notation.asGradleCall() ?: return null
        val kind = platformWrappers[wrapper.calleeExpression?.text] ?: return null
        val block = generateSequence(call.parent) { it.parent }.filterIsInstance<KtCallExpression>()
            .firstOrNull { it.calleeExpression?.text == "dependencies" && it.lambdaArguments.isNotEmpty() } ?: return null
        val scope = when (val enclosing = dependencyScope(block)) {
            GradleBomScope.BUILDSCRIPT -> return null
            GradleBomScope.DIRECT -> GradleBomScope.NESTED
            else -> enclosing
        }
        val configuration = if (name == "add") resolve(call.argument("configurationName", 0))?.text?.takeIf(String::isNotBlank) else name
        val coordinate = coordinates(notation, catalog).singleOrNull()
        val key = coordinate?.let { "${it.group}:${it.artifact}" }
        val version = coordinate?.version?.takeIf { isFixedVersion(it) && !call.hasVersionBlock() && !wrapper.hasVersionBlock() }
        return GradleBomImport(configuration, version, key, kind, scope, source.location(call.textOffset), coordinate?.evidence.orEmpty())
    }

    private fun dependencyScope(block: KtCallExpression): GradleBomScope {
        if (block in topLevelCalls) return GradleBomScope.DIRECT
        val enclosing = generateSequence(block.parent) { it.parent }.filterIsInstance<KtCallExpression>()
            .map { it.calleeExpression?.text }.toSet()
        return when {
            "buildscript" in enclosing -> GradleBomScope.BUILDSCRIPT
            "subprojects" in enclosing -> GradleBomScope.SUBPROJECTS
            "allprojects" in enclosing -> GradleBomScope.ALLPROJECTS
            else -> GradleBomScope.NESTED
        }
    }

    fun dependencies(
        declarations: List<GradleDependencyCall>,
        catalog: GradleCatalog?,
        lockfile: Map<String, List<GradleLock>>,
        platforms: List<GradleBomImport>,
    ): List<DeclaredDependency> {
        val management = springBootManagement(declarations, catalog, platforms)
        val constraints = declarations.filter(GradleDependencyCall::constraint).flatMap { declaration ->
            declaration.coordinates.map { coordinate -> Triple(declaration, coordinate, "${coordinate.group}:${coordinate.artifact}") }
        }
        val pinned = constraints.filter { (_, coordinate, _) -> coordinate.version?.let(::isFixedVersion) == true }
            .groupBy({ it.third }, { it }).mapNotNull { (key, entries) ->
                entries.distinctBy { it.second.version }.singleOrNull()?.let { key to it }
            }.toMap()
        val declared = declarations.filterNot(GradleDependencyCall::constraint).flatMap { declaration ->
            declaration.coordinates.map { coordinate ->
                val key = "${coordinate.group}:${coordinate.artifact}"
                resolvedDependency(declaration, coordinate, lockfile, management, pinned[key])
            }
        }
        val adopted = declared.mapNotNullTo(hashSetOf()) { dependency ->
            val constraint = pinned["${dependency.group}:${dependency.artifact}"]?.first ?: return@mapNotNullTo null
            source.location(constraint.call.textOffset).takeIf { it == dependency.declaredAt }
                ?.let { Triple(it, dependency.group, dependency.artifact) }
        }
        val standalone = constraints.map { (declaration, coordinate, _) ->
            resolvedDependency(declaration, coordinate, lockfile, null, null)
        }.filterNot { Triple(it.declaredAt, it.group, it.artifact) in adopted }
        return declared + standalone
    }

    private fun readDependency(
        statement: KtExpression,
        scope: GradleBomScope,
        catalog: GradleCatalog?,
        errors: MutableList<ParseError>? = null,
    ): GradleDependencyCall? {
        val call = statement.asGradleCall() ?: return null
        val name = call.calleeExpression?.text?.removeSurrounding("`") ?: return null
        if (name in dependencyBlockHelpers) return null
        val location = source.location(call.textOffset)
        val configuration = if (name == "add") {
            val value = resolve(call.argument("configurationName", 0))?.text
            if (value.isNullOrBlank()) {
                errors?.add(ParseError(source.path, location.line, "Не удалось определить конфигурацию зависимости статически"))
                return null
            }
            value
        } else {
            name
        }
        val notationIndex = if (name == "add") 1 else 0
        val notation = call.argument("dependencyNotation", notationIndex)
        val parsed = if (call.hasArgument("group")) {
            listOfNotNull(namedCoordinate(call, notationIndex))
        } else {
            coordinates(notation ?: return null, catalog).ifEmpty { listOfNotNull(namedCoordinate(call, notationIndex)) }
        }
        val coordinates = if (parsed.size == 1) listOf(withRichVersion(call, parsed.single())) else parsed
        val wrapperCall = notation?.withoutParentheses()?.asGradleCall()
        val wrapper = wrapperCall?.calleeExpression?.text
        if (coordinates.isEmpty() && wrapper !in nonExternalNotations) {
            errors?.add(ParseError(source.path, location.line, "Не удалось определить координаты зависимости статически"))
        }
        val platform = platformWrappers[wrapper]
        val richVersion = call.hasVersionBlock() || (platform != null && wrapperCall?.hasVersionBlock() == true)
        return GradleDependencyCall(configuration, call, coordinates, platform, scope, richVersion)
    }

    /** `{ version { strictly("1.2") } }` pins the version of the declaration; require/prefer only fill a missing version. */
    private fun withRichVersion(call: KtCallExpression, coordinate: GradleCoordinate): GradleCoordinate {
        val block = call.lambdaStatements().mapNotNull { it.asGradleCall() }
            .firstOrNull { it.calleeExpression?.text == "version" && it.lambdaArguments.isNotEmpty() } ?: return coordinate
        val rules = block.lambdaStatements().mapNotNull { it.asGradleCall() }
        for (kind in listOf("strictly", "require", "prefer")) {
            val rule = rules.firstOrNull { it.calleeExpression?.text == kind } ?: continue
            if (kind != "strictly" && !coordinate.versionOmitted) return coordinate
            val value = resolve(rule.argument("version", 0)) ?: return coordinate
            return coordinate.copy(
                declaredVersion = value.text, version = value.text, versionOmitted = false, strict = kind == "strictly",
                unresolvedReason = null, evidence = coordinate.evidence + source.location(rule.textOffset) + value.evidence,
            )
        }
        return coordinate
    }

    private fun resolvedDependency(
        declaration: GradleDependencyCall,
        coordinate: GradleCoordinate,
        lockfile: Map<String, List<GradleLock>>,
        management: SpringBootGradleManagement?,
        pinned: Triple<GradleDependencyCall, GradleCoordinate, String>? = null,
    ): DeclaredDependency {
        val configuration = declaration.configuration
        val callLocation = source.location(declaration.call.textOffset)
        val ownLocation = coordinate.declaredAt ?: callLocation
        val key = "${coordinate.group}:${coordinate.artifact}"
        val locks = selectGradleLocks(lockfile[key].orEmpty(), configuration)
        val eligibleManagement = management?.takeIf { declaration.platform == null && declaration.scope != GradleBomScope.BUILDSCRIPT }
        val declaredFixed = coordinate.version?.takeIf(::isFixedVersion)
        val enforced = eligibleManagement?.resolve(key, configuration, declaration.scope, GradleBomMode.ENFORCED)
        val canUseDefault = enforced == null && locks.applicable.isEmpty() && locks.unknown.isEmpty()
        val managed = when {
            !canUseDefault || coordinate.strict -> null
            coordinate.versionOmitted -> eligibleManagement?.resolve(key, configuration, declaration.scope, GradleBomMode.DEFAULT)
            declaredFixed != null -> eligibleManagement?.resolve(key, configuration, declaration.scope, GradleBomMode.CHECK_NATIVE)
            else -> null
        }
        val lockedVersion = locks.version
        val nativeVersionConflict = declaredFixed != null && managed?.version != null && declaredFixed != managed.version
        val enforcedLockConflict = enforced?.version != null && lockedVersion != null && enforced.version != lockedVersion
        val unsettledLock = locks.applicable.isNotEmpty() && lockedVersion == null || locks.unknown.isNotEmpty()
        val pinnedVersion = pinned?.takeIf {
            coordinate.versionOmitted && enforced == null && locks.applicable.isEmpty() && locks.unknown.isEmpty() &&
                managed?.version == null
        }
        val version = when {
            enforcedLockConflict || enforced != null && unsettledLock -> null
            enforced != null -> enforced.version
            locks.applicable.isNotEmpty() -> lockedVersion
            locks.unknown.isNotEmpty() -> null
            nativeVersionConflict -> null
            pinnedVersion != null -> pinnedVersion.second.version
            managed != null -> managed.version
            else -> declaredFixed
        }
        val location = pinnedVersion?.let { source.location(it.first.call.textOffset) } ?: ownLocation
        val reason = when {
            version != null -> null
            enforcedLockConflict -> "Версия из enforcedPlatform Spring Boot BOM расходится с версией в gradle.lockfile"
            enforced?.reason != null -> enforced.reason
            locks.applicable.isNotEmpty() -> "Для зависимости указано несколько версий в применимых конфигурациях gradle.lockfile"
            locks.unknown.isNotEmpty() -> "Не удалось определить применимость конфигураций gradle.lockfile к $configuration"
            nativeVersionConflict -> "Явная версия отличается от рекомендации Spring Boot BOM, итоговая версия не установлена"
            managed?.reason != null -> managed.reason
            coordinate.unresolvedReason != null -> coordinate.unresolvedReason
            coordinate.version != null -> "Объявление не задаёт точную версию"
            !coordinate.versionOmitted -> "Не удалось определить объявленную версию статически"
            else -> "Версия не объявлена и отсутствует в применимых конфигурациях gradle.lockfile"
        }
        val evidence = listOf(location, callLocation, ownLocation) + pinnedVersion?.second?.evidence.orEmpty() + coordinate.evidence + locks.evidence + (enforced ?: managed)?.evidence.orEmpty()
        val bom = enforced?.springBootBom ?: managed?.springBootBom?.takeIf { coordinate.versionOmitted }
        return DeclaredDependency(configuration, coordinate.group, coordinate.artifact, coordinate.declaredVersion,
            version, reason, evidence.distinct(), location, bom?.takeIf { version != null })
    }

    private fun springBootManagement(
        declarations: List<GradleDependencyCall>,
        catalog: GradleCatalog?,
        platforms: List<GradleBomImport>,
    ): SpringBootGradleManagement? {
        val plugins = topLevelCalls.filter { it.calleeExpression?.text == "plugins" }
            .flatMap { it.lambdaStatements().mapNotNull(::pluginRequest) }
            .filter(GradlePluginRequest::applied)
        val dependencyManagementPlugins = plugins.filter { it.id == "io.spring.dependency-management" }
        val automaticImports = if (dependencyManagementPlugins.isEmpty()) emptyList() else {
            plugins.filter { it.id == "org.springframework.boot" }.map { boot ->
                GradleBomImport(null, boot.version?.text?.takeIf(::isFixedVersion), SPRING_BOOT_BOM_COORDINATE, null,
                    GradleBomScope.DIRECT, boot.location,
                    dependencyManagementPlugins.map(GradlePluginRequest::location) + boot.version?.evidence.orEmpty())
            }
        }
        val directDeclarations = declarations.filter { it.scope == GradleBomScope.DIRECT && !it.constraint }
        val imports = automaticImports + platforms
        if (imports.none { it.springBoot || it.kind == GradlePlatformKind.ENFORCED && it.coordinate == null }) return null

        val overrides = buildList {
            topLevelCalls.filter { it.calleeExpression?.text == "dependencyManagement" }
                .forEach { add(GradleVersionOverride(source.location(it.textOffset))) }
            calls.filter(KtCallExpression::isResolutionOverride)
                .forEach { add(GradleVersionOverride(source.location(it.textOffset))) }
            directDeclarations.filter { it.platform == null }.forEach { dependency ->
                addAll(versionOverrides(dependency))
            }
            topLevelCalls.filter { it.calleeExpression?.text == "dependencies" }.forEach { block ->
                block.lambdaStatements().mapNotNull { it.asGradleCall() }
                    .filter { it.calleeExpression?.text == "constraints" }
                    .flatMap { it.lambdaStatements() }
                    .forEach { statement ->
                        val constraint = readDependency(statement, GradleBomScope.DIRECT, catalog)
                        if (constraint == null || constraint.coordinates.isEmpty()) {
                            add(GradleVersionOverride(source.location(statement.textOffset), constraint?.configuration))
                        } else {
                            addAll(versionOverrides(constraint, constraint = true))
                        }
                    }
            }
        }
        val propertyOverrides = if (automaticImports.isEmpty()) emptyList() else bootVersionPropertyOverrides()
        return SpringBootGradleManagement(imports, overrides, propertyOverrides)
    }

    private fun platformImport(dependency: GradleDependencyCall, lockfile: Map<String, List<GradleLock>>): GradleBomImport? {
        val kind = dependency.platform ?: return null
        val coordinate = dependency.coordinates.singleOrNull()
        val key = coordinate?.let { "${it.group}:${it.artifact}" }
        val version = coordinate?.version?.takeIf { isFixedVersion(it) && !dependency.richVersion }
        val locks = if (key == SPRING_BOOT_BOM_COORDINATE && dependency.scope == GradleBomScope.DIRECT) {
            lockfile[key].orEmpty()
        } else emptyList()
        return GradleBomImport(dependency.configuration, version, key, kind, dependency.scope,
            source.location(dependency.call.textOffset), coordinate?.evidence.orEmpty(), locks)
    }

    private fun pluginRequest(expression: KtExpression): GradlePluginRequest? = when (expression) {
        is KtBinaryExpression -> expression.left?.let(::pluginRequest)?.let { request ->
            pluginModifier(request, expression.operationReference.text, expression.right)
        }
        is KtQualifiedExpression -> {
            val modifier = expression.selectorExpression as? KtCallExpression
            val request = pluginRequest(expression.receiverExpression)
            if (modifier == null || request == null) null else {
                pluginModifier(request, modifier.calleeExpression?.text, modifier.argument("version", 0) ?: modifier.argument("apply", 0))
            }
        }
        is KtCallExpression -> if (expression.calleeExpression?.text == "id") {
            stringLiteral(expression.argument("id", 0))?.let { GradlePluginRequest(it, source.location(expression.textOffset)) }
        } else null
        else -> null
    }

    private fun pluginModifier(
        request: GradlePluginRequest,
        modifier: String?,
        value: KtExpression?,
    ): GradlePluginRequest? = when (modifier) {
        "version" -> request.copy(version = resolve(value))
        "apply" -> request.copy(applied = value?.withoutParentheses()?.text == "true")
        else -> null
    }

    private fun versionOverrides(dependency: GradleDependencyCall, constraint: Boolean = false): List<GradleVersionOverride> {
        val richVersion = dependency.richVersion
        return dependency.coordinates.filter { constraint || richVersion || !it.versionOmitted }.map { coordinate ->
            GradleVersionOverride(source.location(dependency.call.textOffset), dependency.configuration,
                "${coordinate.group}:${coordinate.artifact}", plainDeclaration = !constraint && !richVersion)
        }
    }

    private fun bootVersionPropertyOverrides(): List<Location> = buildList {
        for ((name, value) in gradleProperties) {
            if (name.endsWith(".version")) add(value.location)
        }
        for (expression in topLevelExpressions) {
            val name = when (expression) {
                is KtBinaryExpression -> {
                    val access = expression.left as? KtArrayAccessExpression
                    if (expression.operationToken == KtTokens.EQ && isExtra(access?.arrayExpression?.text)) {
                        stringLiteral(access?.indexExpressions?.singleOrNull())
                    } else null
                }
                is KtQualifiedExpression -> {
                    val call = expression.selectorExpression as? KtCallExpression
                    if (call?.calleeExpression?.text == "set" && isExtra(expression.receiverExpression.text)) {
                        stringLiteral(call.argument("name", 0))
                    } else null
                }
                else -> null
            }
            if (name?.endsWith(".version") == true) add(source.location(expression.textOffset))
        }
    }

    private fun namedCoordinate(call: KtCallExpression, notationIndex: Int): GradleCoordinate? {
        val group = resolve(call.argument("group", notationIndex)) ?: return null
        val artifact = resolve(call.argument("name", notationIndex + 1)) ?: return null
        val versionArgument = call.argument("version", notationIndex + 2)
        val version = resolve(versionArgument)
        if (!validCoordinatePart(group.text) || !validCoordinatePart(artifact.text)) return null
        return GradleCoordinate(group.text, artifact.text, stringLiteral(versionArgument) ?: versionArgument?.text,
            version?.text, group.evidence + artifact.evidence + version?.evidence.orEmpty())
    }

    private fun coordinates(expression: KtExpression, catalog: GradleCatalog?): List<GradleCoordinate> {
        val notation = expression.withoutParentheses()
        val call = notation.asGradleCall()
        if (call?.calleeExpression?.text in dependencyWrappers) {
            return call?.argument("notation", 0)?.let { coordinates(it, catalog) }.orEmpty()
        }
        if (call?.calleeExpression?.text == "kotlin") {
            val module = resolve(call.argument("module", 0)) ?: return emptyList()
            if (!validCoordinatePart(module.text)) return emptyList()
            val argument = call.argument("version", 1)
            val version = resolve(argument)
            return listOf(GradleCoordinate("org.jetbrains.kotlin", "kotlin-${module.text}",
                stringLiteral(argument) ?: argument?.text, version?.text, module.evidence + version?.evidence.orEmpty()))
        }
        val catalogEntries = catalog?.lookup(notation.text).orEmpty()
        if (catalogEntries.isNotEmpty()) return catalogEntries
        val declared = if (notation is KtStringTemplateExpression) {
            notation.entries.joinToString("") { entry ->
                if (entry is KtEscapeStringTemplateEntry) entry.unescapedValue else entry.text
            }
        } else {
            null
        }
        val value = resolve(notation)
        return listOfNotNull(coordinate(declared, value?.text, value?.evidence.orEmpty()))
    }

    private fun resolve(expression: KtExpression?, seen: Set<KtExpression> = emptySet()): GradleValue? = when (expression) {
        is KtStringTemplateExpression -> resolveTemplate(expression, seen)
        is KtNameReferenceExpression -> resolveDeclaration(expression.getReferencedName(), seen, expression)
        is KtParenthesizedExpression -> resolve(expression.expression, seen)
        is KtBinaryExpressionWithTypeRHS -> if (expression.right?.text in stringTypes) resolve(expression.left, seen) else null
        is KtBinaryExpression -> if (expression.operationToken == KtTokens.PLUS) {
            val left = resolve(expression.left, seen)
            val right = resolve(expression.right, seen)
            if (left != null && right != null) GradleValue(left.text + right.text, left.evidence + right.evidence) else null
        } else if (expression.operationToken == KtTokens.ELVIS) {
            resolveElvis(expression, seen)
        } else {
            null
        }
        is KtArrayAccessExpression -> if (isExtra(expression.arrayExpression?.text)) {
            stringLiteral(expression.indexExpressions.singleOrNull())?.let { resolveExtra(it, seen) }
        } else {
            null
        }
        is KtQualifiedExpression -> resolveGradleProperty(expression, seen) ?: resolveGetOrElse(expression, seen)
            ?: resolveBuildConstant(expression)
        is KtCallExpression -> resolveGradleProperty(expression, seen)
        else -> null
    }

    private fun resolveBuildConstant(expression: KtQualifiedExpression): GradleValue? {
        if (expression.selectorExpression !is KtNameReferenceExpression) return null
        val segments = expression.text.split('.')
        if (segments.size < 2 || segments.any { !kotlinIdentifier.matches(it) }) return null
        val qualifier = segments.first()
        if (qualifier in declarations || generateSequence(expression.parent) { it.parent }
                .filterIsInstance<KtBlockExpression>()
                .any { block -> block.statements.filterIsInstance<KtProperty>().any { it.name == qualifier } }) {
            return null
        }
        val name = imports[qualifier]?.let { it + "." + segments.drop(1).joinToString(".") } ?: expression.text
        return buildConstants[name]
    }

    private fun resolveTemplate(expression: KtStringTemplateExpression, seen: Set<KtExpression>): GradleValue? {
        val text = StringBuilder()
        val evidence = mutableListOf<Location>()
        for (entry in expression.entries) {
            when (entry) {
                is KtLiteralStringTemplateEntry -> text.append(entry.text)
                is KtEscapeStringTemplateEntry -> text.append(entry.unescapedValue)
                else -> {
                    val value = resolve(entry.expression, seen) ?: return null
                    text.append(value.text)
                    evidence += value.evidence
                }
            }
        }
        return GradleValue(text.toString(), evidence)
    }

    private fun resolveDeclaration(name: String, seen: Set<KtExpression>, reference: KtExpression? = null): GradleValue? {
        val local = reference?.let { expression ->
            generateSequence(expression.parent) { it.parent }.filterIsInstance<KtBlockExpression>()
                .takeWhile { it != psi.script?.blockExpression }
                .firstNotNullOfOrNull { block ->
                    block.statements.filterIsInstance<KtProperty>()
                        .lastOrNull { it.name == name && it.textRange.endOffset <= expression.textOffset }
                }
        }
        val property = local ?: declarations[name] ?: return null
        if (property in seen || property.isVar) return null
        val delegate = property.delegateExpression
        val next = seen + property
        val value = when {
            delegate == null -> resolve(property.initializer, next)
            delegate.text == "project" -> resolveProjectProperty(name, next)
            isExtra(delegate.text) -> resolveExtra(name, next)
            else -> delegate.asGradleCall()?.takeIf { it.calleeExpression?.text == "extra" }
                ?.argument("initialValue", 0)?.let { resolve(it, next) }
        } ?: return null
        return value.copy(evidence = listOf(source.location(property.textOffset)) + value.evidence)
    }

    private fun resolveExtra(name: String, seen: Set<KtExpression>): GradleValue? {
        val (assignment, expression) = extra[name] ?: return null
        if (assignment in seen) return null
        val value = resolve(expression, seen + assignment) ?: return null
        return value.copy(evidence = listOf(source.location(assignment.textOffset)) + value.evidence)
    }

    private fun resolveProjectProperty(name: String, seen: Set<KtExpression>): GradleValue? =
        resolveExtra(name, seen) ?: gradleProperties[name]?.let { GradleValue(it.value, listOf(it.location)) }

    /** `findProperty("x") ?: "1.0"` takes the default only when the property is provably absent. */
    private fun resolveElvis(expression: KtBinaryExpression, seen: Set<KtExpression>): GradleValue? {
        val left = expression.left ?: return null
        resolve(left, seen)?.let { return it }
        return if (isAbsentProperty(left)) resolve(expression.right, seen) else null
    }

    private fun resolveGetOrElse(expression: KtQualifiedExpression, seen: Set<KtExpression>): GradleValue? {
        val call = expression.selectorExpression as? KtCallExpression ?: return null
        if (call.calleeExpression?.text != "getOrElse" && call.calleeExpression?.text != "orElse") return null
        resolve(expression.receiverExpression, seen)?.let { return it }
        return if (isAbsentProperty(expression.receiverExpression)) resolve(call.argument("defaultValue", 0), seen) else null
    }

    private fun isAbsentProperty(expression: KtExpression): Boolean {
        var current = expression.withoutParentheses()
        while (true) {
            current = when {
                current is KtBinaryExpressionWithTypeRHS && current.right?.text in stringTypes -> current.left.withoutParentheses()
                current is KtQualifiedExpression && current.selectorExpression?.text in propertyAdapters ->
                    current.receiverExpression.withoutParentheses()
                else -> break
            }
        }
        val call = current.asGradleCall() ?: return false
        val name = stringLiteral(call.argument("name", 0)) ?: return false
        val receiver = (current as? KtQualifiedExpression)?.receiverExpression?.text
        val defined = name in extra || name in gradleProperties
        return when (call.calleeExpression?.text) {
            "findProperty" -> (receiver == null || receiver == "project") && !defined
            "gradleProperty" -> (receiver == "providers" || receiver == "project.providers") && !defined
            else -> false
        }
    }

    private fun resolveGradleProperty(expression: KtExpression, seen: Set<KtExpression>): GradleValue? {
        val qualified = expression as? KtQualifiedExpression
        val call = expression.asGradleCall()
        val method = qualified?.selectorExpression?.text
        if (method == "get()" || method == "getOrNull()" || method == "orNull" || method == "toString()") {
            return resolve(qualified.receiverExpression, seen)
        }
        val name = stringLiteral(call?.argument("name", 0)) ?: return null
        val receiver = qualified?.receiverExpression?.text
        return when (call?.calleeExpression?.text) {
            "gradleProperty" -> if (receiver == "providers" || receiver == "project.providers") {
                gradleProperties[name]?.let { GradleValue(it.value, listOf(it.location)) }
            } else null
            "property", "findProperty" -> if (receiver == null || receiver == "project") resolveProjectProperty(name, seen) else null
            "get" -> if (isExtra(receiver)) resolveExtra(name, seen) else null
            else -> null
        }
    }
}

private fun KtExpression.withoutParentheses(): KtExpression =
    (this as? KtParenthesizedExpression)?.expression?.withoutParentheses() ?: this

private fun KtCallExpression.lambdaStatements(): List<KtExpression> =
    lambdaArguments.singleOrNull()?.getLambdaExpression()?.bodyExpression?.statements.orEmpty()

private fun KtCallExpression.hasVersionBlock(): Boolean =
    lambdaStatements().any { it.asGradleCall()?.calleeExpression?.text == "version" }

private fun KtCallExpression.isResolutionOverride(): Boolean {
    if (calleeExpression?.text !in resolutionOverrideCalls) return false
    val receiver = (parent as? KtQualifiedExpression)?.receiverExpression?.text
    if (receiver == "resolutionStrategy" || receiver?.endsWith(".resolutionStrategy") == true) return true
    return generateSequence(parent) { it.parent }.filterIsInstance<KtCallExpression>()
        .any { it.calleeExpression?.text == "resolutionStrategy" }
}

private fun KtExpression.asGradleCall(): KtCallExpression? =
    this as? KtCallExpression ?: (this as? KtQualifiedExpression)?.selectorExpression as? KtCallExpression

private fun KtCallExpression.argument(name: String, index: Int): KtExpression? =
    (valueArguments.firstOrNull { it.getArgumentName()?.asName?.asString() == name }
        ?: valueArguments.getOrNull(index)?.takeUnless { it.isNamed() })?.getArgumentExpression()

private fun KtCallExpression.hasArgument(name: String): Boolean =
    valueArguments.any { it.getArgumentName()?.asName?.asString() == name }

private fun stringLiteral(expression: KtExpression?): String? {
    val template = expression as? KtStringTemplateExpression ?: return null
    val text = StringBuilder()
    for (entry in template.entries) {
        when (entry) {
            is KtLiteralStringTemplateEntry -> text.append(entry.text)
            is KtEscapeStringTemplateEntry -> text.append(entry.unescapedValue)
            else -> return null
        }
    }
    return text.toString()
}

private fun coordinate(declared: String?, resolved: String?, evidence: List<Location>): GradleCoordinate? {
    val parts = (resolved ?: declared ?: return null).substringBefore('@').split(':', limit = 4)
    val group = parts.getOrNull(0) ?: return null
    val artifact = parts.getOrNull(1) ?: return null
    if (!validCoordinatePart(group) || !validCoordinatePart(artifact)) return null
    val declaredVersion = (declared ?: resolved).orEmpty().substringBefore('@').split(':', limit = 4).getOrNull(2)
    return GradleCoordinate(group, artifact, declaredVersion, resolved?.let { parts.getOrNull(2) }, evidence)
}

private fun validCoordinatePart(value: String): Boolean = coordinatePart.matches(value)

private fun isFixedVersion(value: String): Boolean = value.isNotBlank() &&
    value.none { it in "[]()," } && !value.endsWith('+') && !value.startsWith("latest.")

private fun isExtra(receiver: String?): Boolean = receiver == "extra" || receiver == "project.extra"

private val kotlinIdentifier = Regex("[A-Za-z_][A-Za-z0-9_]*")
private val coordinatePart = Regex("[A-Za-z0-9_.-]+")
private val propertyAdapters = setOf("toString()", "get()", "getOrNull()", "orNull")
private val stringTypes = setOf("String", "String?", "kotlin.String", "kotlin.String?")
private val platformWrappers = GradlePlatformKind.entries.associateBy(GradlePlatformKind::notation)
private val dependencyWrappers = platformWrappers.keys + "testFixtures"
private val nonExternalNotations = setOf("project", "files", "fileTree", "gradleApi", "localGroovy", "gradleTestKit")
private val dependencyBlockHelpers = setOf("constraints", "components", "modules", "attributes", "exclude", "registerTransform")
private val resolutionOverrideCalls = setOf("force", "eachDependency", "dependencySubstitution")
// A lock on a test classpath describes resolution for the test source set, even when it inherits main dependencies.
internal val jvmClasspathDeclarations = mapOf(
    "compileClasspath" to setOf("api", "implementation", "compileOnly", "compileOnlyApi"),
    "runtimeClasspath" to setOf("api", "implementation", "runtimeOnly"),
    "testCompileClasspath" to setOf("testImplementation", "testCompileOnly"),
    "testRuntimeClasspath" to setOf("testImplementation", "testRuntimeOnly"),
)
internal val jvmDeclarationClasspaths = jvmClasspathDeclarations.entries.flatMap { (classpath, declarations) ->
    declarations.map { it to classpath }
}.groupBy({ it.first }, { it.second }).mapValues { (_, classpaths) -> classpaths.toSet() }
internal val knownGradleConfigurations = jvmClasspathDeclarations.keys + jvmClasspathDeclarations.values.flatten() +
    setOf("annotationProcessor", "testAnnotationProcessor", "classpath", "apiElements", "runtimeElements")
