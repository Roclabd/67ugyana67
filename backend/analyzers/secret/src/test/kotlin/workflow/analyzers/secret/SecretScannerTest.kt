package workflow.analyzers.secret

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeStatus
import java.nio.file.Files
import java.nio.file.Path

class SecretScannerTest {
    @TempDir lateinit var directory: Path
    private val mapper = ObjectMapper()

    @Test
    fun serviceDeskProducesFiveMaskedFindings() {
        val workspace = Path.of(System.getProperty("training.project"))
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val result = scanBuiltInSecrets(model)
            val findings = secretFindings(model, result.candidates)
            assertEquals(5, findings.size(), findings.toString())
            assertEquals(setOf("password", "api-key", "secret-fallback", "recoverable-token", "configuration-token"),
                findings.map { it.path("class").asText() }.toSet())
            assertTrue(result.dismissed.any { it.reason == "environment-reference" })
            assertTrue(result.dismissed.any { it.reason == "non-literal-fallback" })
            assertTrue(result.candidates.none { findings.toString().contains(it.value) })
            assertTrue(findings.all { it.path("secretMasked").asText() == "****" && !it.has("secretHash") })

            System.getenv("C4_EVALUATOR_REPORT")?.let { path ->
                val report = mapper.createObjectNode()
                val rows = report.putArray("findings")
                val fields = listOf("category", "class", "path", "line", "endLine", "severity")
                for (finding in findings) {
                    val row = rows.addObject()
                    fields.filter(finding::has).forEach { row.set<JsonNode>(it, finding[it]) }
                }
                mapper.writeValue(Path.of(path).toFile(), report)
            }
        }
    }

    @Test
    fun configurationDefaultsAndTestFindingsAreHandled() {
        Files.writeString(directory.resolve("application.yml"), """
            security:
              jwt:
                secret: ${'$'}{JWT_SECRET:local-jwt-value-for-test}
            crypto:
              aes:
                key: ${'$'}{AES_KEY}
            legacy:
              password: YOUR_PASSWORD
        """.trimIndent())
        val tests = Files.createDirectories(directory.resolve("src/test/kotlin"))
        Files.writeString(tests.resolve("Fixture.kt"), """val apiKey = "synthetic-test-value"""".trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val scan = scanBuiltInSecrets(model)
            val all = secretFindings(model, scan.candidates)
            val finding = all.single { !it.path("path").asText().startsWith("src/test/") }
            // Секрет из тестов — отдельная находка LOW с пометкой.
            assertEquals("LOW", all.single { it.path("path").asText() == "src/test/kotlin/Fixture.kt" }.path("severity").asText())
            assertEquals("secret-fallback", finding.path("class").asText())
            assertEquals(3, finding.path("line").asInt())
            assertTrue(scan.dismissed.none { it.location.path == "src/test/kotlin/Fixture.kt" && it.reason == "excluded-source" })
            assertTrue(scan.dismissed.any { it.location.line == 6 && it.reason == "environment-reference" })
            assertTrue(scan.dismissed.any { it.location.line == 8 && it.reason == "placeholder" })
            assertEquals(finding, secretFindings(model, scanBuiltInSecrets(model).candidates).single { !it.path("path").asText().startsWith("src/test/") })
            Files.writeString(directory.resolve("application.yml"), "password: new-synthetic-value")
            val changed = requireNotNull(builder.build(directory).model)
            val newFinding = secretFindings(changed, scanBuiltInSecrets(changed).candidates).single { !it.path("path").asText().startsWith("src/test/") }
            assertNotEquals(finding.path("fingerprint"), newFinding.path("fingerprint"))
        }
    }

    @Test
    fun catalogCredentialsAndLowSeverityTestEnvCredentialsAreFindings() {
        val catalog = Files.createDirectories(directory.resolve("gradle")).resolve("libs.versions.toml")
        Files.writeString(catalog, """
            [versions]
            signing-api-key = "fixture-unit-catalog-f7q2"
            jwt = "0.12.6"
        """.trimIndent())
        val testEnv = Files.createDirectories(directory.resolve("src/test")).resolve(".env")
        Files.writeString(testEnv, """
            TEST_PASSWORD=fixture-unit-test-env-d3n8
            TEST_API_KEY=${'$'}{TEST_API_KEY}
            TEST_TOKEN=changeme
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val scan = scanBuiltInSecrets(model)
            val findings = secretFindings(model, scan.candidates)
            val finding = findings.single { it.path("path").asText() == "gradle/libs.versions.toml" }
            assertEquals("api-key", finding.path("class").asText())
            assertEquals(2, finding.path("line").asInt())
            // Секрет в тестах — находка с низкой критичностью и пометкой, а не молчаливое исключение.
            val inTest = findings.single { it.path("path").asText() == "src/test/.env" }
            assertEquals("password", inTest.path("class").asText())
            assertEquals(1, inTest.path("line").asInt())
            assertEquals("LOW", inTest.path("severity").asText())
            assertTrue(inTest.path("title").asText().endsWith("(тестовый код)"))
            assertTrue(scan.dismissed.none { it.reason == "test-source" })
            assertTrue(scan.dismissed.any { it.location == Location("src/test/.env", 2) && it.reason == "environment-reference" })
            assertTrue(scan.dismissed.any { it.location == Location("src/test/.env", 3) && it.reason == "placeholder" })
        }
    }

    @Test
    fun customNodeMasksMatchesAndRejectsUnsupportedExpressions() {
        val value = "synthetic-key-123"
        Files.writeString(directory.resolve("app.properties"), "setting=$value")
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val node = SecretNode(custom = true)
            val params = mapper.createObjectNode().put("pattern", "synthetic-key-[0-9]+")
            val output = runBlocking { node.run(context(params), NodeInput(mapOf("model" to model))) }
            assertEquals(NodeStatus.SUCCESS, output.status)
            assertEquals(1, (output.ports.getValue("findings") as JsonNode).size())
            val customCoverage = mapper.valueToTree<JsonNode>(output.coverage)
            val customRule = customCoverage.path("rules").single()
            assertEquals("secret.custom-regex", customRule.path("id").asText())
            assertEquals(customRule.path("id"), customCoverage.path("rulesApplied").single())
            assertFalse(output.toString().contains(value))
            val builtIn = runBlocking { SecretNode().run(context(mapper.createObjectNode()), NodeInput(mapOf("model" to model))) }
            val builtInCoverage = mapper.valueToTree<JsonNode>(builtIn.coverage)
            val builtInRules = builtInCoverage.path("rules")
            assertEquals(builtInSecretRules, builtInRules.map { it.path("id").asText() })
            assertEquals(builtInSecretRules, builtInCoverage.path("rulesApplied").map(JsonNode::asText))
            assertTrue(builtInRules.all { it.path("title").asText().isNotBlank() && it.path("description").asText().isNotBlank() })
            assertFalse(node.validateParams(mapper.createObjectNode().put("pattern", "(")))
            assertFalse(node.validateParams(mapper.createObjectNode().put("pattern", "(a)\\1")))
        }
    }

    @Test
    fun inputErrorsAndRegexLimitsArePartial() {
        Files.writeString(directory.resolve("Broken.kt"), "fun broken( {")
        Files.writeString(directory.resolve("long.properties"), "value=" + "a".repeat(16_400))
        ProjectModelBuilder().use { builder ->
            val model: ProjectModel = requireNotNull(builder.build(directory).model)
            val input = NodeInput(mapOf("model" to model))
            val builtIn = runBlocking { SecretNode().run(context(mapper.createObjectNode()), input) }
            assertEquals(NodeStatus.PARTIAL, builtIn.status)
            val custom = runBlocking {
                SecretNode(custom = true).run(context(mapper.createObjectNode().put("pattern", "a+")), input)
            }
            assertEquals(NodeStatus.PARTIAL, custom.status)
            assertTrue((custom.ports.getValue("findings") as JsonNode).isEmpty)
        }
    }

    @Test
    fun builtInCoverageCountsTestFilesAndReportsTestParseErrors() {
        Files.writeString(directory.resolve("app.properties"), "setting=fixture")
        val tests = Files.createDirectories(directory.resolve("src/test/kotlin"))
        Files.writeString(tests.resolve("Fixture.kt"), "class Fixture")
        val brokenFile = "src/test/kotlin/Broken.kt"
        Files.writeString(directory.resolve(brokenFile), "class Broken(\n")
        val example = "src/test/.env.example"
        Files.writeString(directory.resolve(example), "TEST_PASSWORD=fixture-example-value")

        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val input = NodeInput(mapOf("model" to model))
            val builtIn = runBlocking { SecretNode().run(context(mapper.createObjectNode()), input) }
            val builtInCoverage = mapper.valueToTree<JsonNode>(builtIn.coverage)
            assertEquals(NodeStatus.PARTIAL, builtIn.status)
            assertEquals("PARTIAL", builtInCoverage.path("status").asText())
            assertEquals(2, builtInCoverage.path("filesAnalyzed").asInt())
            assertEquals(brokenFile, builtInCoverage.path("filesSkipped").single().path("path").asText())
            assertTrue((builtIn.ports.getValue("findings") as JsonNode).isEmpty)
            assertTrue(builtInCoverage.path("dismissed").any {
                it.path("path").asText() == example && it.path("reason").asText() == "excluded-source"
            })

            val custom = runBlocking {
                SecretNode(custom = true).run(context(mapper.createObjectNode().put("pattern", "Fixture")), input)
            }
            val customCoverage = mapper.valueToTree<JsonNode>(custom.coverage)
            assertEquals(NodeStatus.SUCCESS, custom.status)
            assertEquals(1, customCoverage.path("filesAnalyzed").asInt())
            assertTrue(customCoverage.path("filesSkipped").isEmpty)
            assertTrue((custom.ports.getValue("findings") as JsonNode).isEmpty)
        }
    }

    private fun context(parameters: JsonNode) = object : NodeContext {
        override val runId = "test"
        override val nodeId = "secret"
        override val params = parameters
        override val workspace = directory
        override val trigger = mapper.createObjectNode()
        override val coverageStatus = "COMPLETE"
        override fun redact(message: String) = message
        override fun log(message: String) = Unit
        override fun emitProgress(percent: Int, note: String?) = Unit
    }
}
