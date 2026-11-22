package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import workflow.engine.NodeRun
import workflow.engine.NodeStatus
import workflow.engine.RunStatus
import java.nio.file.Files
import java.time.Instant
import java.util.UUID

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:patches;DB_CLOSE_DELAY=-1",
    "workflow.data-dir=build/tmp/patch-sbom-data",
])
@AutoConfigureMockMvc
class PatchAndSbomTest @Autowired constructor(
    private val history: RunStore,
    private val patches: PatchService,
    private val json: ObjectMapper,
    private val mockMvc: MockMvc,
) {
    private fun finding(vararg fields: Pair<String, Any>): Map<String, Any> = mapOf(
        "severity" to "HIGH", "title" to "t", "description" to "d", "remediation" to "r") + fields

    private fun storeRun(findings: List<Map<String, Any>>, dismissedReason: String? = null): RunRecord {
        val coverage = json.valueToTree<JsonNode>(mapOf("status" to "COMPLETE", "dismissed" to listOfNotNull(
            dismissedReason?.let { mapOf("rule" to "sca.maven-advisory", "path" to "build.gradle.kts", "line" to 3, "reason" to it) })))
        val record = RunRecord(UUID.randomUUID().toString(), UUID.randomUUID().toString(), 1,
            json.createObjectNode().put("kind", "manual"), RunStatus.SUCCESS, Instant.parse("2026-01-01T00:00:00Z"),
            finishedAt = Instant.parse("2026-01-01T00:01:00Z"),
            nodeRuns = listOf(NodeRun("sca", NodeStatus.SUCCESS, coverage = coverage)),
            report = json.valueToTree(mapOf("findings" to findings)), workflowName = "demo")
        history.begin(record)
        return record
    }

    private val sca = finding("id" to "sca-aaaa1111", "fingerprint" to "fp-sca", "category" to "SCA",
        "path" to "build.gradle.kts", "line" to 2, "group" to "com.fasterxml.jackson.core", "artifact" to "jackson-databind",
        "version" to "2.9.0", "advisoryId" to "CVE-2020-11619",
        "remediation" to "Обновите com.fasterxml.jackson.core:jackson-databind до версии 2.9.10.4.",
        "evidence" to listOf(mapOf("path" to "build.gradle.kts", "line" to 2)))
    private val secret = finding("id" to "secret-bbbb2222", "fingerprint" to "fp-secret", "category" to "SECRET",
        "path" to "Config.kt", "line" to 1, "class" to "password")
    private val sast = finding("id" to "sast-cccc3333", "fingerprint" to "fp-sast", "category" to "SAST",
        "path" to "A.kt", "line" to 1, "class" to "sql-injection")
    private val bom = finding("id" to "sca-dddd4444", "fingerprint" to "fp-bom", "category" to "SCA",
        "path" to "build.gradle.kts", "line" to 3, "group" to "g", "artifact" to "a", "version" to "1.0", "advisoryId" to "GHSA-1",
        "remediation" to "Выберите релиз Spring Boot BOM.", "evidence" to listOf(mapOf("path" to "build.gradle.kts", "line" to 3)))

    private fun project(): java.nio.file.Path {
        val directory = Files.createTempDirectory("patch-project")
        Files.writeString(directory.resolve("build.gradle.kts"),
            "dependencies {\n    implementation(\"com.fasterxml.jackson.core:jackson-databind:2.9.0\")\n    implementation(\"g:a:\${v}\")\n}\n")
        Files.writeString(directory.resolve("Config.kt"), "val dbPassword = \"Zx9kQ2mLp0w\"\n")
        return directory
    }

    @Test fun `patch endpoint serves sca and secret diffs with no-store and handles failures`() {
        val run = storeRun(listOf(sca, secret, sast, bom))
        patches.capture(run.id, run.report!!, project())

        mockMvc.get("/api/runs/${run.id}/findings/sca-aaaa1111/patch").andExpect {
            status { isOk() }
            header { string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")) }
            content { contentTypeCompatibleWith("text/x-diff") }
            content { string(org.hamcrest.Matchers.containsString("+    implementation(\"com.fasterxml.jackson.core:jackson-databind:2.9.10.4\")")) }
        }
        val secretUrl = "/api/runs/${run.id}/findings/secret-bbbb2222/patch"
        mockMvc.get(secretUrl).andExpect {
            status { isOk() }
            header { string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")) }
            content { string(org.hamcrest.Matchers.containsString("-val dbPassword = \"Zx9kQ2mLp0w\"")) }
        }
        mockMvc.get(secretUrl) { param("masked", "true") }.andExpect {
            status { isOk() }
            content { string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Zx9kQ2mLp0w"))) }
        }
        mockMvc.get(secretUrl) { with { it.remoteAddr = "10.1.2.3"; it } }.andExpect {
            status { isForbidden() }
            header { string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")) }
        }
        mockMvc.get("/api/runs/${run.id}/findings/unknown/patch").andExpect { status { isNotFound() } }
        mockMvc.get("/api/runs/${run.id}/findings/sast-cccc3333/patch").andExpect {
            status { isNotFound() }
            jsonPath("$.message") { value(NO_AUTOFIX_MESSAGE) }
        }
        mockMvc.get("/api/runs/${run.id}/findings/sca-dddd4444/patch").andExpect { status { isConflict() } }
    }

    @Test fun `patch is gone when the snapshot was not kept`() {
        val run = storeRun(listOf(sca))
        mockMvc.get("/api/runs/${run.id}/findings/sca-aaaa1111/patch").andExpect { status { isGone() } }
        mockMvc.get("/api/runs/${UUID.randomUUID()}/findings/sca-aaaa1111/patch").andExpect { status { isNotFound() } }
    }

    @Test fun `sbom is a valid cyclonedx 1_5 document with components and vulnerabilities`() {
        val run = storeRun(listOf(sca), dismissedReason = "Версия org.slf4j:slf4j-api:2.0.9 вне уязвимых диапазонов справочника")
        val body = mockMvc.get("/api/runs/${run.id}/sbom.cdx.json").andExpect {
            status { isOk() }
            content { contentTypeCompatibleWith("application/vnd.cyclonedx+json") }
        }.andReturn().response.contentAsString
        val root = json.readTree(body)
        assertEquals("CycloneDX", root.path("bomFormat").asText())
        assertEquals("1.5", root.path("specVersion").asText())
        assertTrue(root.path("serialNumber").asText().matches(Regex("urn:uuid:[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")))
        assertEquals("2026-01-01T00:01:00Z", root.path("metadata").path("timestamp").asText())
        assertTrue(root.path("metadata").path("tools").path("components").size() >= 1)
        assertEquals("application", root.path("metadata").path("component").path("type").asText())
        val components = root.path("components")
        assertEquals(2, components.size())
        val purls = components.map { it.path("purl").asText() }
        assertTrue("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.0" in purls)
        assertTrue("pkg:maven/org.slf4j/slf4j-api@2.0.9" in purls)
        for (component in components) {
            assertEquals("library", component.path("type").asText())
            assertTrue(component.path("purl").asText().matches(Regex("pkg:maven/[^/@]+/[^/@]+@[^@/]+")))
            assertEquals(component.path("purl").asText(), component.path("bom-ref").asText())
            assertTrue(component.hasNonNull("group") && component.hasNonNull("name") && component.hasNonNull("version"))
        }
        val vulnerability = root.path("vulnerabilities").single()
        assertEquals("CVE-2020-11619", vulnerability.path("id").asText())
        assertEquals("NVD", vulnerability.path("source").path("name").asText())
        assertEquals("high", vulnerability.path("ratings").first().path("severity").asText())
        assertEquals("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.0", vulnerability.path("affects").first().path("ref").asText())
        mockMvc.get("/api/runs/${UUID.randomUUID()}/sbom.cdx.json").andExpect { status { isNotFound() } }
    }
}
