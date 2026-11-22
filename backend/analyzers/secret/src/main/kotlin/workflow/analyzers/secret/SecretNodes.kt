package workflow.analyzers.secret

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.google.re2j.Pattern
import com.google.re2j.PatternSyntaxException
import codeguard.analyzers.model.ProjectModel
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
class SecretConfiguration {
    @Bean
    fun secretNode(): NodeDefinition = SecretNode()

    @Bean
    fun customSecretRuleNode(): NodeDefinition = SecretNode(custom = true)
}

internal class SecretNode(private val custom: Boolean = false) : NodeDefinition {
    override val type = if (custom) "analyzer.secret.regex" else "analyzer.secret"
    override val title = if (custom) "Своё regex-правило для секретов" else "Поиск секретов"
    override val category = NodeCategory.ANALYZER
    override val inputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
    override val outputs = listOf(PortSpec("findings", PortType.FINDINGS))
    override val secretParams = if (custom) setOf("pattern") else emptySet()
    override val paramsSchema = JsonNodeFactory.instance.objectNode().apply {
        put("type", "object")
        put("additionalProperties", false)
        val properties = putObject("properties")
        if (custom) {
            properties.putObject("pattern").put("type", "string")
                .put("minLength", 1).put("maxLength", MAX_CUSTOM_SECRET_PATTERN_LENGTH)
            putArray("required").add("pattern")
        } else {
            properties.putObject("minSeverity").put("type", "string").put("default", "LOW")
                .putArray("enum").add("LOW").add("MEDIUM").add("HIGH").add("CRITICAL")
        }
    }

    override fun validateParams(params: JsonNode): Boolean = !custom || compilePattern(params) != null

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.Default) {
        val model = input.ports["model"] as? ProjectModel ?: return@withContext failed()
        val scan: SecretRuleResult
        val incomplete: Boolean
        if (custom) {
            val pattern = compilePattern(ctx.params) ?: return@withContext failed()
            val result = scanCustomSecrets(model, pattern)
            scan = SecretRuleResult(result.candidates, emptyList())
            incomplete = result.incomplete
            if (incomplete) ctx.log("Достигнут лимит пользовательского поиска. Часть входных данных не проверена.")
        } else {
            scan = scanBuiltInSecrets(model)
            incomplete = false
        }

        val isExcluded = if (custom) ::isCustomSecretScanExcluded else ::isBuiltInSecretScanExcluded
        val relevantFiles = model.files.filter {
            !isExcluded(it.path) && if (custom) it.isCustomSecretSource() else (it.isBuiltInSecretSource() || it.isForeignSecretSource())
        }.mapTo(hashSetOf()) { it.path }
        val parseErrors = model.parseErrors.filterNot { isExcluded(it.path) }
        val skipped = parseErrors.map { error ->
            buildMap<String, Any> {
                put("path", error.path)
                put("reason", "Ошибка чтения или разбора входного файла")
                error.line?.let { put("line", it) }
            }
        }
        val status = if (incomplete || skipped.isNotEmpty()) NodeStatus.PARTIAL else NodeStatus.SUCCESS
        val dismissed = scan.dismissed.map { mapOf(
            "path" to it.location.path,
            "line" to it.location.line,
            "rule" to it.rule,
            "reason" to it.reason,
        ) }
        val findings = secretFindings(model, scan.candidates, ctx.params.path("minSeverity").asText("LOW"))
        val appliedRules = if (custom) listOf("secret.custom-regex") else builtInSecretRules
        NodeOutput(mapOf("findings" to findings), status, mapOf(
            "status" to if (status == NodeStatus.SUCCESS) "COMPLETE" else "PARTIAL",
            "filesAnalyzed" to relevantFiles.count { path -> parseErrors.none { it.path == path } },
            "filesSkipped" to skipped,
            "rulesApplied" to appliedRules,
            "rules" to SecretRuleCatalog.applied(appliedRules),
            "unresolved" to emptyList<Any>(),
            "dismissed" to dismissed,
        ), rulesVersion = ANALYZER_RULES_VERSION)
    }

    private fun failed() = NodeOutput(emptyMap(), NodeStatus.FAILED, mapOf(
        "status" to "FAILED",
        "filesAnalyzed" to 0,
        "filesSkipped" to emptyList<Any>(),
        "rulesApplied" to emptyList<String>(),
        "rules" to emptyList<CoverageRule>(),
        "unresolved" to emptyList<Any>(),
        "dismissed" to emptyList<Any>(),
    ))

    private fun compilePattern(params: JsonNode): Pattern? {
        val pattern = params.path("pattern").textValue() ?: return null
        if (pattern.isBlank() || pattern.length > MAX_CUSTOM_SECRET_PATTERN_LENGTH) return null
        return try {
            Pattern.compile(pattern)
        } catch (_: PatternSyntaxException) {
            null
        }
    }
}
