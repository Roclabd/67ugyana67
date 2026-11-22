package workflow.analyzers.sca

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import workflow.engine.GraphValidator
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeRegistry
import workflow.engine.NodeStatus
import java.nio.file.Files
import java.nio.file.Path

class CustomScaRuleNodeTest {
    @TempDir
    lateinit var workspace: Path

    private val mapper = ObjectMapper()

    @Test
    fun matchesOnlyTheConfiguredCoordinateUsingTheLockedVersion() {
        write("build.gradle.kts", """
            dependencies {
                implementation("example:client:0.9")
                implementation("other:client:1.5")
            }
        """)
        write("gradle.lockfile", "example:client:1.1.0=compileClasspath")
        write("utilities/build.gradle.kts", """
            dependencies {
                implementation("example:client:2.0.0")
            }
        """)
        write("utilities/gradle.lockfile", "example:client:2.0.0=compileClasspath")
        val output = scan(params().put("lowerVersion", "1.1").put("severity", "HIGH"))

        assertEquals(NodeStatus.SUCCESS, output.status)
        val finding = output.findings().single()
        assertEquals("SCA", finding.path("category").asText())
        assertEquals("HIGH", finding.path("severity").asText())
        assertEquals("1.1.0", finding.path("version").asText())
        assertEquals("build.gradle.kts", finding.path("path").asText())
        assertEquals(2, finding.path("line").asInt())
        assertTrue(finding.path("advisoryId").asText().matches(Regex("POLICY-[0-9a-f]{64}")))
        assertEquals(listOf("build.gradle.kts", "gradle.lockfile"), finding.path("evidence").map { it.path("path").asText() })
        val coverage = output.coverage()
        assertEquals(4, coverage.path("filesAnalyzed").asInt())
        assertEquals("utilities/build.gradle.kts", coverage.path("dismissed").single().path("path").asText())
        val rule = coverage.path("rules").single()
        assertEquals(rule.path("id"), finding.path("rule"))
        assertEquals(rule.path("id"), coverage.path("rulesApplied").single())
        assertTrue(rule.path("title").asText().contains("example:client"))
        assertTrue(rule.path("description").asText().contains("[1.1, 2.0)"))
    }

    @Test
    fun reportsUnresolvedTargetVersionsAndKeepsKnownFindings() {
        write("build.gradle.kts", """
            dependencies {
                implementation("example:client:1.5")
                implementation("other:client:1.+")
                implementation("example:client:1.+")
                implementation("example:client:1.5-RC1")
            }
        """)
        val output = scan()
        assertEquals(NodeStatus.PARTIAL, output.status)
        assertEquals("1.5", output.findings().single().path("version").asText())
        val coverage = output.coverage()
        assertEquals("PARTIAL", coverage.path("status").asText())
        val unresolved = coverage.path("unresolved")
        assertEquals(listOf(4, 5), unresolved.map { it.path("line").asInt() })
        assertTrue(unresolved.all {
            it.path("kind").asText() == "dependency-version" && it.path("subject").asText() == "example:client"
        })
    }

    @Test
    fun reportsGradleParseErrorsEvenWhenTheTargetCoordinateIsMissing() {
        write("build.gradle.kts", """
            dependencies {
                implementation(unknownDependency)
                implementation("other:client:1.+")
            }
        """)

        val output = scan()
        assertEquals(NodeStatus.PARTIAL, output.status)
        assertTrue(output.findings().isEmpty())
        val coverage = output.coverage()
        assertTrue(coverage.path("unresolved").isEmpty)
        assertEquals(0, coverage.path("filesAnalyzed").asInt())
        assertEquals(2, coverage.path("filesSkipped").single().path("line").asInt())
    }

    @Test
    fun validatesGraphParametersAndUsesStableIdentityForEquivalentBounds() {
        AnnotationConfigApplicationContext(CustomScaRuleConfiguration::class.java).use { context ->
            val registry = NodeRegistry(context.getBeansOfType(NodeDefinition::class.java).values.toList())
            val node = requireNotNull(registry["analyzer.sca.custom"])
            val validator = GraphValidator(registry)
            assertTrue(validator.parameterErrors(node.type, params().put("lowerVersion", "")).isEmpty())
            assertFalse(validator.parameterErrors(node.type, params().put("coordinate", "example:client:1")).isEmpty())
            assertFalse(validator.parameterErrors(node.type, params().put("upperVersion", "2.0-RC1")).isEmpty())
            assertFalse(validator.parameterErrors(node.type, params().put("lowerVersion", "3")).isEmpty())
            assertFalse(validator.parameterErrors(node.type, params().put("lowerVersion", "2.0.0")).isEmpty())
            assertFalse(validator.parameterErrors(node.type, params().put("upperInclusive", "true")).isEmpty())
        }

        write("build.gradle.kts", """
            dependencies {
                implementation("example:client:2.0.0")
            }
        """)
        val exact = params().put("lowerVersion", "2").put("upperInclusive", true)
        val equivalent = params().put("lowerVersion", "02.00.0").put("upperVersion", "02.00").put("upperInclusive", true)
        val first = scan(exact).findings().single()
        val second = scan(equivalent).findings().single()
        assertEquals(first.path("fingerprint"), second.path("fingerprint"))
        assertEquals(first.path("advisoryId"), second.path("advisoryId"))
        assertEquals("MEDIUM", first.path("severity").asText())
        assertTrue(scan().findings().isEmpty())
        assertEquals(NodeStatus.FAILED, scan(params().put("lowerVersion", "2.0.0")).status)
    }

    private fun params(): ObjectNode = mapper.createObjectNode()
        .put("coordinate", "example:client").put("upperVersion", "2.0")

    private fun write(path: String, text: String) {
        val file = workspace.resolve(path)
        Files.createDirectories(file.parent)
        Files.writeString(file, text.trimIndent())
    }

    private fun scan(params: ObjectNode = params()): NodeOutput = ProjectModelBuilder().use { builder ->
        val built = builder.build(workspace)
        val model = requireNotNull(built.model) { built.summary.toString() }
        val context = object : NodeContext {
            override val runId = "test-run"
            override val nodeId = "custom-sca"
            override val params = params
            override val workspace = this@CustomScaRuleNodeTest.workspace
            override val trigger = mapper.createObjectNode()
            override val coverageStatus = built.summary.status.name
            override fun redact(message: String) = message
            override fun log(message: String) = Unit
            override fun emitProgress(percent: Int, note: String?) = Unit
        }
        runBlocking { CustomScaRuleNode().run(context, NodeInput(mapOf("model" to model))) }
    }

    private fun NodeOutput.findings(): List<JsonNode> = (ports.getValue("findings") as JsonNode).toList()

    private fun NodeOutput.coverage(): JsonNode = mapper.valueToTree(coverage)
}
