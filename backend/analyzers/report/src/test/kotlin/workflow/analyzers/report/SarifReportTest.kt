package workflow.analyzers.report

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SarifReportTest {
    private val mapper = ObjectMapper()

    @Test
    fun indexesSortedRulesAndUsesCoverageMetadataAndFindingSeverity() {
        val report = mapper.readTree("""
            {
              "sourceSubdir": "repo module",
              "coverage": {
                "status": "PARTIAL",
                "byAnalyzer": {
                  "filtered": {"rulesApplied": ["sast.tls.trust-all"]},
                  "sca": {"rules": [
                    {"id": "sca.maven-advisory", "title": "Уязвимые зависимости", "description": "Сверяет версии со справочником."}
                  ]},
                  "duplicate": {"rules": [
                    {"id": "sca.maven-advisory", "title": "Уязвимые зависимости", "description": "Сверяет версии со справочником."}
                  ]}
                }
              },
              "findings": [
                {"category": "SCA", "severity": "CRITICAL", "path": "build.gradle.kts", "line": 9,
                   "advisoryId": "CVE-2020-1234", "rule": "sca.maven-advisory"},
                {"category": "SAST", "severity": "LOW", "path": "src/имя #1.kt", "line": 1, "endLine": 3,
                   "class": "sql-injection", "fingerprint": "${"b".repeat(64)}"}
              ]
            }
        """.trimIndent())
        val sarif = sarifReport(mapper, report)
        assertEquals("2.1.0", sarif.path("version").asText())
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", sarif.path("\$schema").asText())
        val run = sarif.path("runs").single()
        assertEquals("PARTIAL", run.at("/properties/coverageStatus").asText())
        assertFalse(run.at("/invocations/0/executionSuccessful").asBoolean(true))
        assertEquals(PRODUCT_NAME, run.at("/tool/driver/name").asText())
        val rules = run.at("/tool/driver/rules")
        assertEquals(listOf("sast.sql.taint-to-query", "sast.tls.trust-all", "sca.maven-advisory"),
            rules.map { it.path("id").asText() })
        assertEquals("Уязвимые зависимости", rules[2].at("/shortDescription/text").asText())
        assertEquals("Сверяет версии со справочником.", rules[2].at("/fullDescription/text").asText())
        assertEquals(listOf("security", "SCA"), rules[2].at("/properties/tags").map(JsonNode::asText))

        val results = run.path("results")
        for (result in results) {
            assertEquals(result.path("ruleId"), rules[result.path("ruleIndex").asInt()].path("id"))
            assertEquals("fail", result.path("kind").asText())
        }
        assertEquals("error", results[0].path("level").asText())
        assertEquals("CRITICAL", results[0].at("/properties/severity").asText())
        assertTrue(results[0].at("/message/text").asText().contains("CVE-2020-1234"))
        assertEquals("note", results[1].path("level").asText())
        assertEquals("SAST", results[1].at("/properties/category").asText())
        assertEquals("repo%20module/src/%D0%B8%D0%BC%D1%8F%20%231.kt", location(results[1]).at("/artifactLocation/uri").asText())
        assertEquals(1, location(results[1]).at("/region/startLine").asInt())
        assertEquals(3, location(results[1]).at("/region/endLine").asInt())
        assertEquals("b".repeat(64), fingerprint(results[1]))
        assertFalse(results[1].has("partialFingerprints"))
        assertEquals(sarif, sarifReport(mapper, report))
    }

    @Test
    fun exportsOnlyStaticSecretWordingAndUsesLocationIdentity() {
        val canary = "synthetic-secret-for-export-test"
        val internalHash = "a".repeat(64)
        val report = mapper.readTree("""
            {
              "coverage": {"byAnalyzer":{"secret":{"rules":[
                {"id":"secret.custom-regex","title":"$canary","description":"$canary"}
              ]}}},
              "findings": [{
                "category":"SECRET", "class":"custom-regex", "rule":"secret.$canary",
                "severity":"HIGH", "path":"app.conf", "line":6, "title":"$canary", "description":"$canary",
                "remediation":"$canary", "secretMasked":"$canary", "secretHash":"$internalHash", "fingerprint":"$internalHash",
                "evidence":[{"path":"app.conf","line":6,"note":"$canary"}], "ai":{"fixExample":"$canary"}
              }]
            }
        """.trimIndent())
        val sarif = sarifReport(mapper, report)
        val result = sarif.at("/runs/0/results/0")
        assertEquals("secret.custom-regex", result.path("ruleId").asText())
        assertEquals("Пользовательское regex-правило", result.at("/message/text").asText())
        assertFalse(sarif.toString().contains(canary))
        assertFalse(sarif.toString().contains(internalHash))
        assertTrue(Regex("[a-f0-9]{64}").matches(fingerprint(result)))
        val finding = report.at("/findings/0") as ObjectNode
        finding.put("fingerprint", "d".repeat(64))
        assertEquals(sarif, sarifReport(mapper, report))
        finding.put("line", 7)
        assertNotEquals(fingerprint(result), fingerprint(sarifReport(mapper, report).at("/runs/0/results/0")))
    }

    @Test
    fun validatesLocationsAndSupportsLegacyResultsWithoutInventingLines() {
        val report = mapper.createObjectNode().put("sourceSubdir", "../external")
        val input = report.putArray("findings")
        val badPaths = listOf("", ".", "/etc/main.kt", "C:\\a.kt", "\\\\host\\project\\a.kt",
            "https://example.org/a.kt", "../a.kt", "src/../a.kt", "src/.. /a.kt", "src/bad\nfile.kt", "src/")
        for (path in badPaths) {
            input.addObject().put("category", "SAST").put("path", path).put("line", 1)
        }
        input.addObject().put("category", "SAST").put("path", "invalid-line.kt").put("line", 0)
        input.addObject().put("category", "SAST").put("path", "string-line.kt").put("line", "2")
        input.addObject().put("category", "SAST").put("path", "src\\100%.kt").put("line", 3).put("endLine", 2)
        input.addObject().put("category", "SCA").put("path", "build.gradle.kts")
        val run = sarifReport(mapper, report).path("runs").single()
        val locations = run.path("results").map(::location)
        assertEquals(listOf("build.gradle.kts", "src/100%25.kt"), locations.map { it.at("/artifactLocation/uri").asText() })
        assertFalse(locations[0].has("region"))
        assertEquals(3, locations[1].at("/region/startLine").asInt())
        assertFalse(locations[1].path("region").has("endLine"))
        assertEquals("warning", run.at("/results/1/level").asText())
        assertFalse(run.has("invocations"))
    }

    @Test
    fun emptyInputHasOneRunAndEmptyRuleAndResultArrays() {
        val run = sarifReport(mapper, mapper.createArrayNode()).path("runs").single()
        assertEquals(mapper.createArrayNode(), run.at("/tool/driver/rules"))
        assertEquals(mapper.createArrayNode(), run.path("results"))
    }

    private fun location(result: JsonNode): JsonNode = result.at("/locations/0/physicalLocation")

    private fun fingerprint(result: JsonNode): String = result.path("fingerprints").path("codeguardFinding/v1").asText()
}
