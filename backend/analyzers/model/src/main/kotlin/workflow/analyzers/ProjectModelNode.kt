package workflow.analyzers

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import codeguard.analyzers.model.ModelStatus
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import java.nio.file.Path

@Configuration(proxyBeanMethods = false)
class ProjectModelConfiguration {
    @Bean(destroyMethod = "close")
    fun projectModelBuilder() = ProjectModelBuilder()

    @Bean
    fun projectModelNode(builder: ProjectModelBuilder): NodeDefinition = ProjectModelNode(builder)
}

class ProjectModelNode(private val builder: ProjectModelBuilder) : NodeDefinition {
    override val type = "analyzer.parse"
    override val title = "Разбор проекта"
    override val category = NodeCategory.ANALYZER
    override val inputs = listOf(PortSpec("workspace", PortType.WORKSPACE))
    override val outputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
    override val paramsSchema = JsonNodeFactory.instance.objectNode()
        .put("type", "object").put("additionalProperties", false)

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = runInterruptible(Dispatchers.IO) {
        val workspace = input.ports["workspace"] as? Path
            ?: return@runInterruptible NodeOutput(emptyMap(), NodeStatus.FAILED, coverage("FAILED", 0, emptyList()))
        val result = builder.build(workspace)
        val model = result.model
            ?: return@runInterruptible NodeOutput(emptyMap(), NodeStatus.FAILED, coverage("FAILED", 0, emptyList()))
        val skipped = model.parseErrors.map { error ->
            buildMap<String, Any> {
                put("path", error.path)
                put("reason", error.message)
                error.line?.let { put("line", it) }
            }
        }
        val skippedPaths = model.parseErrors.map { it.path }.toSet()
        val analyzed = model.files.count { it.path !in skippedPaths }
        val status = if (result.summary.status == ModelStatus.COMPLETE) NodeStatus.SUCCESS else NodeStatus.PARTIAL
        NodeOutput(
            mapOf("model" to model),
            status,
            coverage(result.summary.status.name, analyzed, skipped, ProjectModelRuleCatalog.applied(model), model),
        )
    }

    private fun coverage(
        status: String,
        analyzed: Int,
        skipped: List<Map<String, Any>>,
        rules: List<CoverageRule> = emptyList(),
        model: codeguard.analyzers.model.ProjectModel? = null,
    ) = mapOf(
        "status" to status,
        "filesAnalyzed" to analyzed,
        "filesSkipped" to skipped,
        "rulesApplied" to rules.map { it.id },
        "rules" to rules,
        "unresolved" to emptyList<Any>(),
        "dismissed" to emptyList<Any>(),
        "languages" to model?.languages.orEmpty().map { mapOf("name" to it.name, "files" to it.files, "sastSupported" to it.sastSupported, "script" to it.script) },
        "ignoredDirectories" to model?.ignoredDirectories.orEmpty(),
    )
}
