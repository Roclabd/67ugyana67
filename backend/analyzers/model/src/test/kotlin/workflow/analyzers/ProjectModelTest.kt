package workflow.analyzers

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import codeguard.analyzers.model.ConfigKind
import codeguard.analyzers.model.ModelStatus
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeStatus
import workflow.engine.Redaction
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat

class ProjectModelTest {
    @TempDir
    lateinit var workspace: Path

    @Test
    fun serviceDeskSnapshotHasIndexedMetadata() {
        val project = Path.of(System.getProperty("training.project"))
        ProjectModelBuilder().use { builder ->
            val result = builder.build(project)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            assertTrue("build.gradle.kts" in model.kotlin)
            assertTrue(model.declarations.byName.isNotEmpty())
            assertTrue(model.calls.byFile.isNotEmpty())
            val json = model.gradle.dependencies.single { it.group == "org.json" && it.artifact == "json" }
            assertEquals("20230227", json.resolvedVersion)
            assertEquals(38, json.declaredAt.line)
            assertTrue(json.resolution.any { it.path == "gradle.properties" && it.line == 1 })
            assertFalse(model.gradle.dependencies.any { it.artifact in setOf("snakeyaml", "kotlin-stdlib") })
            assertEquals(6, model.spring.endpoints.size)
            assertEquals(5, model.spring.securityRules.size)
            assertTrue(model.spring.securityRules.zipWithNext().all { (left, right) ->
                left.location.line <= right.location.line
            })
            assertTrue(model.spring.corsConfigs.isNotEmpty())
            assertTrue(model.spring.repositories.isNotEmpty())
            assertTrue(model.sqlSchema.tables.values.any { "customer_id" in it.ownerColumns })
            assertTrue(model.config.any { it.line == 17 && it.kind == ConfigKind.ENV })
        }
    }

    @Test
    fun malformedFileDoesNotShiftOriginalLinesOrPreventPartialModel() {
        val bytes = "\uFEFFpackage lab\r\n\r\nfun answer() = 42\r\n".toByteArray()
        Files.write(workspace.resolve("Good.kt"), bytes)
        Files.writeString(workspace.resolve("Broken.kt"), "fun broken( {\n")
        Files.writeString(workspace.resolve("application.yml"), "app:\n  key: example\n")
        val mapper = ObjectMapper()

        ProjectModelBuilder().use { builder ->
            val node = ProjectModelNode(builder)
            val output = runBlocking {
                node.run(context(mapper), NodeInput(mapOf("workspace" to workspace)))
            }
            assertEquals(NodeStatus.PARTIAL, output.status)
            val coverage = mapper.valueToTree<JsonNode>(output.coverage)
            val rules = coverage.path("rules")
            val ruleIds = rules.map { it.path("id").asText() }
            assertTrue("model.kotlin.symbol-index" in ruleIds)
            assertTrue("model.spring.web-security" in ruleIds)
            assertEquals(ruleIds, coverage.path("rulesApplied").map(JsonNode::asText))
            assertTrue(rules.all { it.path("title").asText().isNotBlank() && it.path("description").asText().isNotBlank() })
            val model = output.ports.getValue("model") as ProjectModel
            assertEquals(3, model.declarations.byName.getValue("answer").single().location.line)
            assertEquals(2, model.config.single().line)
            assertEquals(
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                model.files.single { it.path == "Good.kt" }.sha256,
            )
            assertTrue(model.parseErrors.any { it.path == "Broken.kt" && it.line == 1 })
            assertFalse("Broken.kt" in model.kotlin)
            assertEquals(
                mapOf("model" to mapOf("kind" to "PROJECT_MODEL")),
                Redaction(mapper, emptyList()).ports(output.ports, node.outputs),
            )
        }
    }

    @Test
    fun gradleOnlyCoverageDoesNotListSpringChecks() {
        Files.writeString(workspace.resolve("settings.gradle.kts"), "rootProject.name = \"fixture\"")
        val mapper = ObjectMapper()
        ProjectModelBuilder().use { builder ->
            val output = runBlocking {
                ProjectModelNode(builder).run(context(mapper), NodeInput(mapOf("workspace" to workspace)))
            }
            assertEquals(NodeStatus.SUCCESS, output.status)
            val coverage = mapper.valueToTree<JsonNode>(output.coverage)
            assertEquals(listOf("model.kotlin.symbol-index", "model.gradle-dependencies"),
                coverage.path("rulesApplied").map(JsonNode::asText))
        }
    }

    @Test
    fun missingWorkspaceFails() {
        ProjectModelBuilder().use { builder ->
            val node = ProjectModelNode(builder)
            val output = runBlocking {
                node.run(context(ObjectMapper()), NodeInput(mapOf("workspace" to workspace.resolve("missing"))))
            }
            assertEquals(NodeStatus.FAILED, output.status)
            assertTrue(output.ports.isEmpty())
        }
    }

    private fun context(mapper: ObjectMapper) = object : NodeContext {
        override val runId = "test-run"
        override val nodeId = "project-model"
        override val params = mapper.createObjectNode()
        override val workspace = this@ProjectModelTest.workspace
        override val trigger = mapper.createObjectNode()
        override val coverageStatus = "PARTIAL"
        override fun redact(message: String) = message
        override fun log(message: String) = Unit
        override fun emitProgress(percent: Int, note: String?) = Unit
    }
}
