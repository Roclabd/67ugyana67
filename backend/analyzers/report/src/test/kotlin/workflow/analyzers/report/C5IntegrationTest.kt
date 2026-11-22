package workflow.analyzers.report

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import workflow.analyzers.sca.ScaNode
import workflow.analyzers.secret.SecretNode
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeStatus
import java.nio.file.Files
import java.nio.file.Path

class C5IntegrationTest {
    @TempDir lateinit var directory: Path
    private val mapper = ObjectMapper()
    private val exporter = DefaultReportExporter(mapper)

    @Test
    fun findingsFromBothNodesExportWithMatchingRulesVersion() {
        val workspace = Path.of(System.getProperty("training.project"))
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val input = NodeInput(mapOf("model" to model))
            val secrets = runBlocking { SecretNode().run(context(workspace), input) }
            val sca = runBlocking { ScaNode().run(context(workspace), input) }
            assertEquals(secrets.rulesVersion, sca.rulesVersion)
            val scaCoverage = mapper.valueToTree<JsonNode>(sca.coverage)
            val scaRule = scaCoverage.path("rules").single()
            assertEquals(scaCoverage.path("rulesApplied").single(), scaRule.path("id"))
            assertTrue(scaRule.path("title").asText().isNotBlank())
            assertTrue(scaRule.path("description").asText().isNotBlank())
            val findings = mapper.createArrayNode()
                .addAll(secrets.ports.getValue("findings") as ArrayNode)
                .addAll(sca.ports.getValue("findings") as ArrayNode)
            val dependencies = findings.filter { it.path("category").asText() == "SCA" }
            assertEquals(5, dependencies.size)
            assertTrue(dependencies.all { it.path("fixedVersions").isArray })
            assertTrue(dependencies.none { it.path("artifact").asText() in setOf("snakeyaml", "kotlin-stdlib") })

            val report = mapper.createObjectNode().set<JsonNode>("findings", findings)
            val json = exporter.json(report)
            assertEquals(10, json.path("findings").size())
            assertEquals("SECRET", json.path("findings").first().path("category").asText())
            assertFalse(json.toString().contains("secretMasked"))
            assertFalse(json.toString().contains("fingerprint"))

            val duplicates = mapper.createArrayNode().apply {
                findings.reversed().forEach { add(it) }
                add(findings.first())
            }
            assertEquals(json, exporter.json(mapper.createObjectNode().set<JsonNode>("findings", duplicates)))
            System.getenv("C5_EVALUATOR_REPORT")?.let { mapper.writeValue(Path.of(it).toFile(), json) }
        }
    }

    @Test
    fun scaCoverageSeparatesDependenciesAndDisplaysCountsInMarkdown() {
        Files.writeString(directory.resolve("build.gradle.kts"), """
            dependencies {
                implementation("org.apache.commons:commons-text:1.9-rc1")
                implementation("org.apache.commons:commons-text:1.10.0")
                implementation("example:fixture:1.0")
            }
        """.trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val output = runBlocking { ScaNode().run(context(directory), NodeInput(mapOf("model" to model))) }
            assertEquals(NodeStatus.PARTIAL, output.status)
            assertTrue((output.ports.getValue("findings") as ArrayNode).isEmpty)
            val coverage = mapper.valueToTree<JsonNode>(output.coverage)
            assertEquals("org.apache.commons:commons-text", coverage.path("unresolved").first().path("subject").asText())
            val counts = coverage.path("dependencyCoverage")
            assertEquals(1, counts.path("checked").asInt())
            assertEquals(1, counts.path("withoutAdvisories").asInt())
            assertEquals(1, counts.path("unresolvedVersion").asInt())
            val snapshotDate = coverage.path("advisorySources").first().path("snapshotDate").asText()
            assertTrue(snapshotDate.isNotBlank())
            val report = mapper.createObjectNode()
            report.putObject("coverage").put("status", "PARTIAL").putObject("byAnalyzer").set<JsonNode>("sca", coverage)
            val markdown = exporter.markdown(report)
            assertTrue(markdown.contains("сверено со справочником: 1"))
            assertTrue(markdown.contains("известна версия, но нет записей: 1"))
            assertTrue(markdown.contains("версия не установлена или не поддерживается: 1"))
            assertTrue(markdown.contains("дата снимка $snapshotDate"))
            assertEquals(mapper.readTree("""{"findings":[]}"""), exporter.json(report))
        }
    }

    @Test
    fun trailingZeroMatchesNumericRangeAndAliasIsDeduplicated() {
        Files.writeString(directory.resolve("build.gradle.kts"), """
            dependencies { implementation("org.apache.commons:commons-text:1.9.0") }
        """.trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val output = runBlocking { ScaNode().run(context(directory), NodeInput(mapOf("model" to model))) }
            val findings = output.ports.getValue("findings") as ArrayNode
            val finding = findings.single()
            assertEquals("1.9.0", finding.path("version").asText())
            assertEquals("CVE-2022-42889", finding.path("advisoryId").asText())
            findings.add((finding as com.fasterxml.jackson.databind.node.ObjectNode).deepCopy()
                .put("advisoryId", "GHSA-599f-7c49-w659"))
            val report = mapper.createObjectNode().set<JsonNode>("findings", findings)
            val exported = exporter.json(report).path("findings").single()
            assertEquals("CVE-2022-42889", exported.path("advisoryId").asText())
        }
    }

    @Test
    fun markdownDisplaysCoverageAndLeavesSecretPayloadOut() {
        val report = mapper.readTree("""
            {
              "coverage": {
                "status": "PARTIAL",
                "byAnalyzer": {
                  "secret": {
                    "status": "PARTIAL", "filesAnalyzed": 3,
                    "filesSkipped": [{"path":"app.yml","reason":"Ошибка чтения"}],
                    "rulesApplied": ["secret.password"],
                    "rules": [{ "id": "secret.password", "title": "Проверка паролей", "description": "Ищет литералы в свойствах" }],
                    "unresolved": [], "dismissed": []
                  }
                }
              },
              "findings": [{
                "category":"SECRET", "path":"main.kt", "class":"password", "line":2,
                "secretMasked":"synthetic-unmasked-test-value", "description":"synthetic-unmasked-test-value"
              }]
            }
        """.trimIndent())
        val markdown = exporter.markdown(report)
        assertTrue(markdown.contains("PARTIAL"))
        assertTrue(markdown.contains("app.yml"))
        assertTrue(markdown.contains("Проверка паролей (secret.password) — Ищет литералы в свойствах"))
        assertFalse(markdown.contains("Объявления зависимостей"))
        assertFalse(exporter.json(report).has("coverage"))
        assertTrue(markdown.contains("NOT_RECEIVED"))
        assertFalse(markdown.contains("synthetic-unmasked-test-value"))
        assertFalse(exporter.json(report).toString().contains("synthetic-unmasked-test-value"))
    }

    private fun context(workspacePath: Path) = object : NodeContext {
        override val runId = "c5-test"
        override val nodeId = "test"
        override val params = mapper.createObjectNode()
        override val workspace = workspacePath
        override val trigger = mapper.createObjectNode()
        override val coverageStatus = "COMPLETE"
        override fun redact(message: String) = message
        override fun log(message: String) = Unit
        override fun emitProgress(percent: Int, note: String?) = Unit
    }
}
