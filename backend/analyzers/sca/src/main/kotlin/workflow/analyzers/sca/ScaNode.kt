package workflow.analyzers.sca

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import codeguard.analyzers.model.DeclaredDependency
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceFile
import codeguard.analyzers.model.SourceType
import codeguard.analyzers.model.SpringBootBomUse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import workflow.analyzers.ANALYZER_RULES_VERSION
import workflow.analyzers.CoverageRule
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import java.io.IOException
import java.security.MessageDigest
import java.util.HexFormat

@Configuration(proxyBeanMethods = false)
class ScaConfiguration {
    @Bean
    fun scaNode(): NodeDefinition = ScaNode()
}

private const val SCA_RULE = "sca.maven-advisory"
private const val BUNDLED_CATALOG = "/sca/vulnerabilities.json"
private val advisoryRule = CoverageRule(
    SCA_RULE,
    "Уязвимые зависимости",
    "Сверяет установленные версии объявленных Gradle-зависимостей с диапазонами встроенного справочника и справочников проекта.",
)

internal class ScaNode : NodeDefinition {
    override val type = "analyzer.sca"
    override val title = "Проверка зависимостей"
    override val category = NodeCategory.ANALYZER
    override val inputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
    override val outputs = listOf(PortSpec("findings", PortType.FINDINGS))
    override val paramsSchema = JsonNodeFactory.instance.objectNode()
        .put("type", "object").put("additionalProperties", false)

    private val database by lazy {
        try {
            ScaNode::class.java.getResourceAsStream(BUNDLED_CATALOG)?.use { AdvisoryDatabase.read(it) }
        } catch (_: IOException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.Default) {
        val model = input.ports["model"] as? ProjectModel ?: return@withContext failed()
        val bundled = database ?: run {
            ctx.log("Не удалось загрузить справочник SCA")
            return@withContext failed()
        }
        val files = model.files.filter { isGradleInput(it.path) }.associateBy { it.path }
        val parseErrors = model.parseErrors.filter { isGradleInput(it.path) || isAdvisoryCatalog(it.path) }
        val skippedPaths = parseErrors.mapTo(hashSetOf()) { it.path }
        val skipped = parseErrors.map { error ->
            buildMap<String, Any> {
                put("path", error.path)
                put("reason", if (isAdvisoryCatalog(error.path)) error.message else "Ошибка чтения или разбора входного файла Gradle")
                error.line?.let { put("line", it) }
            }
        }.distinct().toMutableList()
        val sources = mutableListOf(AdvisorySource("builtin", BUNDLED_CATALOG, bundled.size, bundled.snapshotDate))
        var advisories = bundled
        val projectCatalogs = model.files.filter { it.type == SourceType.ADVISORY_DATABASE }.sortedBy { it.path }
        for (catalog in projectCatalogs) {
            val project = try {
                catalog.text.byteInputStream().use(AdvisoryDatabase::read)
            } catch (_: IOException) {
                skipped += mapOf("path" to catalog.path, "reason" to "Некорректный JSON справочника SCA")
                continue
            } catch (_: InvalidAdvisoryRange) {
                skipped += mapOf("path" to catalog.path, "reason" to "Некорректные границы диапазона версий в справочнике SCA")
                continue
            } catch (_: IllegalArgumentException) {
                skipped += mapOf("path" to catalog.path, "reason" to "Неподдерживаемый формат или некорректная запись справочника SCA")
                continue
            }
            sources += AdvisorySource("project", catalog.path, project.size, project.snapshotDate)
            advisories = advisories.overlay(project)
        }
        // Менеджеры зависимостей, кроме Gradle Kotlin DSL: честно сообщаем, что их манифесты не проверялись.
        model.files.asSequence().mapNotNull { file -> unsupportedManifest(file.path)?.let { file.path to it } }
            .take(MAX_UNSUPPORTED_MANIFESTS).forEach { (path, ecosystem) ->
                skipped += mapOf("path" to path, "reason" to "$ecosystem не поддерживается — анализируются Gradle Kotlin DSL")
            }
        val unresolved = mutableListOf<Map<String, Any>>()
        val dismissed = mutableListOf<Map<String, Any>>()
        val findings = JsonNodeFactory.instance.arrayNode()
        val sourceLines = mutableMapOf<String, List<String>>()
        val emitted = hashSetOf<FindingKey>()
        var partial = skipped.isNotEmpty()
        var checkedDependencies = 0
        var dependenciesWithoutAdvisories = 0
        var unresolvedVersions = 0

        val dependencies = model.gradle.dependencies.sortedWith(compareBy(
            { it.declaredAt.path }, { it.declaredAt.line }, { it.group }, { it.artifact },
        ))
        for (dependency in dependencies) {
            val location = dependency.declaredAt
            val coordinate = Coordinate(dependency.group, dependency.artifact)
            val records = advisories.byCoordinate[coordinate].orEmpty()
            val version = NumericVersion.parseDependency(dependency.resolvedVersion)
            if (version == null) {
                unresolvedVersions++
                unresolved += mapOf(
                    "kind" to "dependency-version",
                    "path" to location.path,
                    "line" to location.line,
                    "subject" to coordinate.toString(),
                    "reason" to unresolvedReason(dependency),
                )
                if (records.isNotEmpty()) partial = true
                continue
            }
            if (records.isEmpty()) {
                dependenciesWithoutAdvisories++
                continue
            }

            checkedDependencies++
            val matches = records.filter { it.affects(version) }.sortedBy(Advisory::id)
            if (matches.isEmpty()) {
                dismissed += mapOf(
                    "rule" to SCA_RULE,
                    "path" to location.path,
                    "line" to location.line,
                    "reason" to "Версия $coordinate:${version.text} вне уязвимых диапазонов справочника",
                )
                continue
            }
            val file = files.getValue(location.path)
            val fragment = sourceLines.getOrPut(location.path) { file.text.lines() }
                .getOrNull(location.line - 1).orEmpty().trim()
            val upgrade = safeUpgrade(version, records, matches)
            for (advisory in matches) {
                if (emitted.add(FindingKey(location.path, coordinate, version.text, advisory.id))) {
                    findings.appendFinding(dependency, coordinate, version, advisory, file, fragment, upgrade)
                }
            }
        }

        NodeOutput(
            ports = mapOf("findings" to findings),
            status = if (partial) NodeStatus.PARTIAL else NodeStatus.SUCCESS,
            coverage = mapOf(
                "status" to if (partial) "PARTIAL" else "COMPLETE",
                "filesAnalyzed" to files.keys.count { it !in skippedPaths },
                "filesSkipped" to skipped,
                "rulesApplied" to listOf(advisoryRule.id),
                "rules" to listOf(advisoryRule),
                "advisorySources" to sources,
                "advisoryCount" to advisories.size,
                "dependencyCoverage" to mapOf(
                    "checked" to checkedDependencies,
                    "withoutAdvisories" to dependenciesWithoutAdvisories,
                    "unresolvedVersion" to unresolvedVersions,
                ),
                "springBootBoms" to dependencies.springBootBoms(),
                "unresolved" to unresolved.distinct(),
                "dismissed" to dismissed.distinct(),
            ),
            rulesVersion = ANALYZER_RULES_VERSION,
        )
    }

    private fun failed() = NodeOutput(emptyMap(), NodeStatus.FAILED, mapOf(
        "status" to "FAILED",
        "filesAnalyzed" to 0,
        "filesSkipped" to emptyList<Any>(),
        "rulesApplied" to emptyList<String>(),
        "rules" to emptyList<CoverageRule>(),
        "unresolved" to emptyList<Any>(),
        "dismissed" to emptyList<Any>(),
    ), rulesVersion = ANALYZER_RULES_VERSION)
}

@JsonInclude(JsonInclude.Include.NON_NULL)
private data class AdvisorySource(val source: String, val path: String, val records: Int, val snapshotDate: String?)

private fun isAdvisoryCatalog(path: String): Boolean = path.substringAfterLast('/') == "vulnerabilities.json"

private data class FindingKey(val path: String, val coordinate: Coordinate, val version: String, val advisoryId: String)

private const val MAX_UNSUPPORTED_MANIFESTS = 100

private val unsupportedManifestNames = mapOf(
    "pom.xml" to "Maven (pom.xml)",
    "build.gradle" to "Gradle Groovy DSL (build.gradle)",
    "package.json" to "npm (package.json)",
    "pyproject.toml" to "Python (pyproject.toml)",
    "pipfile" to "Python (Pipfile)",
    "go.mod" to "Go (go.mod)",
    "cargo.toml" to "Rust (Cargo.toml)",
    "conanfile.txt" to "Conan (conanfile.txt)",
    "conanfile.py" to "Conan (conanfile.py)",
    "vcpkg.json" to "vcpkg (vcpkg.json)",
    "packages.config" to "NuGet (packages.config)",
    "composer.json" to "Composer (composer.json)",
    "gemfile" to "Bundler (Gemfile)",
    "pubspec.yaml" to "Dart (pubspec.yaml)",
    "mix.exs" to "Mix (mix.exs)",
)

/** Название экосистемы и манифеста, если файл — манифест зависимостей, который SCA не разбирает. */
internal fun unsupportedManifest(path: String): String? {
    val name = path.substringAfterLast('/').lowercase()
    unsupportedManifestNames[name]?.let { return it }
    return when {
        name.startsWith("requirements") && name.endsWith(".txt") -> "Python (${path.substringAfterLast('/')})"
        name.endsWith(".csproj") || name.endsWith(".fsproj") || name.endsWith(".vbproj") ->
            ".NET (${path.substringAfterLast('/')})"
        else -> null
    }
}

private val gradleMetadataNames =setOf("gradle.properties", "gradle.lockfile")

internal fun isGradleInput(path: String): Boolean = path.endsWith(".gradle.kts") ||
    path.substringAfterLast('/') in gradleMetadataNames ||
    path == "gradle/libs.versions.toml" || path.endsWith("/gradle/libs.versions.toml")

internal fun unresolvedReason(dependency: DeclaredDependency): String = if (dependency.resolvedVersion == null) {
    dependency.unresolvedReason ?: "Не удалось установить точную версию зависимости"
} else {
    "Формат версии не поддерживается правилами SCA"
}

private fun safeUpgrade(current: NumericVersion, records: List<Advisory>, matches: List<Advisory>): NumericVersion? =
    matches.asSequence().flatMap { it.fixedVersions.asSequence() }
        .filter { candidate -> candidate > current && records.none { it.affects(candidate) } }
        .minWithOrNull(compareBy<NumericVersion> { it }.thenBy { it.text })

private fun ArrayNode.appendFinding(
    dependency: DeclaredDependency,
    coordinate: Coordinate,
    version: NumericVersion,
    advisory: Advisory,
    file: SourceFile,
    fragment: String,
    upgrade: NumericVersion?,
) {
    val location = dependency.declaredAt
    val fingerprint = hashScaFields(
        "SCA", coordinate.group, coordinate.artifact, version.text, advisory.id, location.path,
        location.line.toString(), fragment, file.sha256,
    )
    val remediation = when {
        dependency.springBootBom != null ->
            "Выберите релиз Spring Boot BOM, управляющий $coordinate версией вне уязвимых диапазонов."
        upgrade != null -> "Обновите $coordinate до версии ${upgrade.text}."
        else -> "Проверьте доступные обновления $coordinate по диапазонам справочника."
    }
    val finding = addObject()
        .put("id", "sca-$fingerprint")
        .put("fingerprint", fingerprint)
        .put("category", "SCA")
        .put("path", location.path)
        .put("line", location.line)
        .put("severity", advisory.severity)
        .put("rule", SCA_RULE)
        .put("group", coordinate.group)
        .put("artifact", coordinate.artifact)
        .put("version", version.text)
        .put("advisoryId", advisory.id)
        .put("title", "Уязвимая версия $coordinate")
        .put("description", "Версия ${version.text} входит в диапазон записи ${advisory.id}.")
        .put("remediation", remediation)
    val fixedVersions = finding.putArray("fixedVersions")
    advisory.fixedVersions.forEach { fixedVersions.add(it.text) }
    finding.putArray("evidence").appendDependencyEvidence(dependency)
}

internal fun Iterable<DeclaredDependency>.springBootBoms(): List<Map<String, Any>> =
    mapNotNull(DeclaredDependency::springBootBom).distinct()
        .sortedWith(compareBy({ it.declaredAt.path }, { it.declaredAt.line }, SpringBootBomUse::release))
        .map { mapOf("release" to it.release, "path" to it.declaredAt.path, "line" to it.declaredAt.line) }

internal fun ArrayNode.appendDependencyEvidence(dependency: DeclaredDependency) {
    val bom = dependency.springBootBom
    val locations = (listOf(dependency.declaredAt) + dependency.resolution + listOfNotNull(bom?.declaredAt)).distinct()
    for (source in locations) {
        val item = addObject().put("path", source.path).put("line", source.line)
        source.endLine?.takeIf { it > source.line }?.let { item.put("endLine", it) }
        if (bom != null && source == bom.declaredAt) item.put("note", "Версия из Spring Boot BOM ${bom.release}")
    }
}

internal fun hashScaFields(vararg fields: String): String =
    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
        .digest(fields.joinToString("") { it.length.toString() + ":" + it }.toByteArray(Charsets.UTF_8)))
