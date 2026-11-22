package workflow.analyzers.sca

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import codeguard.analyzers.model.DeclaredDependency
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceFile
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

@Configuration(proxyBeanMethods = false)
class CustomScaRuleConfiguration {
    @Bean
    fun customScaRuleNode(): NodeDefinition = CustomScaRuleNode()
}

internal class CustomScaRuleNode : NodeDefinition {
    override val type = "analyzer.sca.custom"
    override val title = "Своё правило SCA/конфигурации"
    override val description = "Проверяет объявления зависимости Gradle по заданному диапазону версий."
    override val category = NodeCategory.ANALYZER
    override val inputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
    override val outputs = listOf(PortSpec("findings", PortType.FINDINGS))
    override val paramsSchema = JsonNodeFactory.instance.objectNode().apply {
        put("type", "object")
        put("additionalProperties", false)
        putArray("required").add("coordinate").add("upperVersion")
        val properties = putObject("properties")
        properties.putObject("coordinate").put("type", "string").put("title", "Координаты Maven")
            .put("description", "Точные координаты в формате group:artifact.")
            .put("maxLength", MAX_COORDINATE_LENGTH).put("pattern", "^${coordinatePattern.pattern}$")
        properties.putObject("lowerVersion").put("type", "string").put("title", "Нижняя граница")
            .put("description", "Числовая версия, например 1.2.0. Пустое поле означает диапазон без нижней границы.")
            .put("maxLength", MAX_VERSION_LENGTH).put("pattern", "^(?:$VERSION_PATTERN)?$")
        properties.putObject("lowerInclusive").put("type", "boolean").put("title", "Включить нижнюю границу")
            .put("default", true)
        properties.putObject("upperVersion").put("type", "string").put("title", "Верхняя граница")
            .put("description", "Числовая версия, например 2.0.")
            .put("maxLength", MAX_VERSION_LENGTH).put("pattern", "^$VERSION_PATTERN$")
        properties.putObject("upperInclusive").put("type", "boolean").put("title", "Включить верхнюю границу")
            .put("default", false)
        properties.putObject("severity").put("type", "string").put("title", "Критичность")
            .put("default", DEFAULT_SEVERITY).putArray("enum").also { options -> severities.forEach { options.add(it) } }
    }

    override fun validateParams(params: JsonNode): Boolean = parsePolicy(params) != null

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.Default) {
        val model = input.ports["model"] as? ProjectModel ?: return@withContext failed()
        val policy = parsePolicy(ctx.params) ?: return@withContext failed()
        val files = model.files.filter { isGradleInput(it.path) }.associateBy { it.path }
        val parseErrors = model.parseErrors.filter { isGradleInput(it.path) }
        val skippedPaths = parseErrors.mapTo(hashSetOf()) { it.path }
        val skipped = parseErrors.map { error ->
            buildMap<String, Any> {
                put("path", error.path)
                put("reason", "Ошибка чтения или разбора входного файла Gradle")
                error.line?.let { put("line", it) }
            }
        }.distinct()
        val findings = JsonNodeFactory.instance.arrayNode()
        val unresolved = mutableListOf<Map<String, Any>>()
        val dismissed = mutableListOf<Map<String, Any>>()
        val sourceLines = mutableMapOf<String, List<String>>()
        val emitted = hashSetOf<Pair<String, String>>()
        val dependencies = model.gradle.dependencies.filter {
            it.group == policy.coordinate.group && it.artifact == policy.coordinate.artifact
        }.sortedWith(compareBy({ it.declaredAt.path }, { it.declaredAt.line }))

        for (dependency in dependencies) {
            val location = dependency.declaredAt
            val version = NumericVersion.parseDependency(dependency.resolvedVersion)
            when {
                version == null -> unresolved += mapOf(
                    "kind" to "dependency-version",
                    "path" to location.path,
                    "line" to location.line,
                    "subject" to policy.coordinate.toString(),
                    "reason" to unresolvedReason(dependency),
                )
                version !in policy.range -> dismissed += mapOf(
                    "rule" to policy.rule.id,
                    "path" to location.path,
                    "line" to location.line,
                    "reason" to "Версия ${policy.coordinate}:${version.text} вне запрещённого диапазона ${policy.rangeLabel}",
                )
                emitted.add(location.path to version.text) -> {
                    val file = files.getValue(location.path)
                    val fragment = sourceLines.getOrPut(location.path) { file.text.lines() }
                        .getOrNull(location.line - 1).orEmpty().trim()
                    findings.appendPolicyFinding(policy, dependency, version, file, fragment)
                }
            }
        }

        val partial = skipped.isNotEmpty() || unresolved.isNotEmpty()
        NodeOutput(
            ports = mapOf("findings" to findings),
            status = if (partial) NodeStatus.PARTIAL else NodeStatus.SUCCESS,
            coverage = mapOf(
                "status" to if (partial) "PARTIAL" else "COMPLETE",
                "filesAnalyzed" to files.keys.count { it !in skippedPaths },
                "filesSkipped" to skipped,
                "rulesApplied" to listOf(policy.rule.id),
                "rules" to listOf(policy.rule),
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

private data class DependencyPolicy(val coordinate: Coordinate, val range: VersionRange, val severity: String) {
    val rangeLabel: String = range.label { it.text }
    private val identity = hashScaFields(coordinate.toString(), range.label(NumericVersion::canonicalText))
    val advisoryId = "POLICY-$identity"
    val rule = CoverageRule(
        id = "sca.custom-dependency-policy.$identity",
        title = "Пользовательское правило для $coordinate",
        description = "Проверяет, входит ли версия $coordinate в запрещённый диапазон $rangeLabel.",
    )
}

private const val VERSION_PATTERN = "[0-9]+(?:\\.[0-9]+)*"
private const val MAX_VERSION_LENGTH = 128
private const val MAX_COORDINATE_LENGTH = 256
private const val DEFAULT_SEVERITY = "MEDIUM"
private val severities = listOf("LOW", "MEDIUM", "HIGH", "CRITICAL")
private val coordinatePattern = Regex("([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)")

private fun parsePolicy(params: JsonNode): DependencyPolicy? {
    val coordinate = params.path("coordinate").textValue()?.takeIf { it.length <= MAX_COORDINATE_LENGTH }
        ?.let(coordinatePattern::matchEntire) ?: return null
    val (group, artifact) = coordinate.destructured
    val upper = boundedVersion(params.path("upperVersion").textValue()) ?: return null
    val lower = if (params.has("lowerVersion")) {
        val value = params.path("lowerVersion").textValue() ?: return null
        if (value.isEmpty()) null else boundedVersion(value) ?: return null
    } else null
    val lowerInclusive = params.booleanOrDefault("lowerInclusive", true) ?: return null
    val upperInclusive = params.booleanOrDefault("upperInclusive", false) ?: return null
    val severity = if (params.has("severity")) params.path("severity").textValue() ?: return null else DEFAULT_SEVERITY
    if (severity !in severities) return null
    val range = try {
        VersionRange(lower, lowerInclusive, upper, upperInclusive)
    } catch (_: InvalidAdvisoryRange) {
        return null
    }
    return DependencyPolicy(Coordinate(group, artifact), range, severity)
}

private fun boundedVersion(value: String?): NumericVersion? =
    NumericVersion.parse(value?.takeIf { it.length <= MAX_VERSION_LENGTH })

private fun JsonNode.booleanOrDefault(name: String, default: Boolean): Boolean? =
    if (has(name)) path(name).takeIf(JsonNode::isBoolean)?.booleanValue() else default

private fun VersionRange.label(render: (NumericVersion) -> String): String {
    val opening = if (lower != null && lowerInclusive) "[" else "("
    val closing = if (upperInclusive) "]" else ")"
    return "$opening${lower?.let(render) ?: "−∞"}, ${render(upper)}$closing"
}

private fun NumericVersion.canonicalText(): String =
    text.split('.').map { it.trimStart('0').ifEmpty { "0" } }
        .dropLastWhile { it == "0" }.joinToString(".").ifEmpty { "0" }

private fun ArrayNode.appendPolicyFinding(
    policy: DependencyPolicy,
    dependency: DeclaredDependency,
    version: NumericVersion,
    file: SourceFile,
    fragment: String,
) {
    val location = dependency.declaredAt
    val fingerprint = hashScaFields(
        "SCA", policy.coordinate.group, policy.coordinate.artifact, version.text, policy.advisoryId,
        location.path, location.line.toString(), fragment, file.sha256,
    )
    val evidence = addObject()
        .put("id", "sca-$fingerprint")
        .put("fingerprint", fingerprint)
        .put("category", "SCA")
        .put("path", location.path)
        .put("line", location.line)
        .put("severity", policy.severity)
        .put("rule", policy.rule.id)
        .put("group", policy.coordinate.group)
        .put("artifact", policy.coordinate.artifact)
        .put("version", version.text)
        .put("advisoryId", policy.advisoryId)
        .put("title", "Версия ${policy.coordinate} запрещена политикой проекта")
        .put("description", "Версия ${version.text} входит в запрещённый диапазон ${policy.rangeLabel}.")
        .put("remediation", "Выберите версию ${policy.coordinate} вне диапазона ${policy.rangeLabel}.")
        .putArray("evidence")
    evidence.appendDependencyEvidence(dependency)
}
