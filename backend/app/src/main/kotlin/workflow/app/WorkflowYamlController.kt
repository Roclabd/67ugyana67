package workflow.app

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.core.StreamReadFeature
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.*
import workflow.engine.Workflow
import workflow.nodes.InputRejected

@RestController
@RequestMapping("/api/workflows")
class WorkflowYamlController(
    private val workflows: WorkflowStore,
    private val json: ObjectMapper,
    private val repositories: RepositorySettingsStore,
) {
    private val yaml = YAMLMapper.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .build()

    @GetMapping("/{id}/export.yaml", produces = ["text/yaml;charset=UTF-8"])
    fun export(@PathVariable id: String): String {
        val portable = workflows.withoutSecrets(workflows.get(id)).copy(id = null, version = 0)
        return yaml.writeValueAsString(json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(portable))
    }

    @PostMapping("/import.yaml", consumes = ["text/yaml", "application/yaml", "application/x-yaml"])
    @ResponseStatus(HttpStatus.CREATED)
    fun import(@RequestBody body: String): Workflow {
        if (body.isBlank() || body.length > 256_000) throw InputRejected("YAML должен содержать до 256 000 символов.")
        val workflow = try {
            val tree = yaml.readTree(body)
            if (tree?.isObject != true) throw InputRejected("Ожидается один сценарий в YAML.")
            json.treeToValue(tree, Workflow::class.java)
        } catch (_: JsonProcessingException) {
            throw InputRejected("Проверьте синтаксис YAML и поля сценария.")
        }
        repositories.approveGraph(workflow)
        return workflows.create(workflow.copy(id = null, version = 0))
    }
}
