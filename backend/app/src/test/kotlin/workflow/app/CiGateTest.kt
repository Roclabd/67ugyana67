package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import workflow.engine.RunStatus
import java.time.Instant

class CiGateTest {
    private val json = ObjectMapper()
    private val sha = "a".repeat(40)
    private val run = RunRecord("run", "workflow", 1, json.createObjectNode().put("commitSha", sha), RunStatus.SUCCESS, Instant.now(),
        report = json.readTree("""{"coverage":{"status":"COMPLETE","analyzerTypes":{"a":"analyzer.secret","b":"analyzer.sca","c":"analyzer.sast"},"byAnalyzer":{"a":{"status":"COMPLETE"},"b":{"status":"COMPLETE"},"c":{"status":"COMPLETE"}}},"inputHash":"$sha","rulesVersion":"v1"}"""),
        coverageStatus = "COMPLETE", commitsVerified = true, rulesVersions = setOf("v1"), counts = mapOf("CRITICAL" to 0))

    @Test fun `only complete verified report without critical findings is accepted`() {
        assertTrue(CiGate.decide(run, sha, "v1").pass)
        for (state in listOf(RunStatus.RUNNING, RunStatus.PARTIAL, RunStatus.FAILED)) {
            assertFalse(CiGate.decide(run.copy(status = state), sha, "v1").pass)
        }
        assertFalse(CiGate.decide(run.copy(coverageStatus = "PARTIAL"), sha, "v1").pass)
        assertFalse(CiGate.decide(run.copy(coverageStatus = "FAILED"), sha, "v1").pass)
        assertFalse(CiGate.decide(run.copy(counts = emptyMap()), sha, "v1").pass)
        assertEquals("CRITICAL_FINDINGS", CiGate.decide(run.copy(counts = mapOf("CRITICAL" to 1)), sha, "v1").reason)
        assertEquals("COMMIT_MISMATCH", CiGate.decide(run, "b".repeat(40), "v1").reason)
        assertEquals("COMMIT_MISMATCH", CiGate.decide(run.copy(commitsVerified = false), sha, "v1").reason)
        assertEquals("RULES_VERSION_MISMATCH", CiGate.decide(run, sha, "v2").reason)
        assertEquals("RULES_VERSION_MISMATCH", CiGate.decide(run, sha, null).reason)
    }

    @Test fun `gate requires completed secret sca and sast analyzers`() {
        val noSast = (run.report as ObjectNode).deepCopy().also { (it.path("coverage") as ObjectNode).with("analyzerTypes").remove("c") }
        val d = CiGate.decide(run.copy(report = noSast), sha, "v1")
        assertFalse(d.pass); assertEquals("MISSING_ANALYZERS", d.reason); assertEquals(listOf("SAST"), d.missingAnalyzers)
        val failedSca = (run.report as ObjectNode).deepCopy().also { ((it.path("coverage") as ObjectNode).with("byAnalyzer").path("b") as ObjectNode).put("status", "FAILED") }
        assertEquals(listOf("SCA"), CiGate.decide(run.copy(report = failedSca), sha, "v1").missingAnalyzers)
    }

    @Test fun `combined reports use the same rule versions as the server policy`() {
        val expected = "codeguard-rules-v2+sast-1"
        val signedReport = (run.report as ObjectNode).deepCopy().put("rulesVersion", expected)
        val combined = run.copy(report = signedReport, rulesVersions = setOf("sast-1", "codeguard-rules-v2"))

        assertEquals(GateDecision(true, "PASS"), CiGate.decide(combined, sha, expected))
        assertTrue(CiGate.decide(combined, sha, "sast-1+codeguard-rules-v2", expected).pass)
        assertFalse(CiGate.decide(combined, sha, expected, "codeguard-rules-v2+sast-2").pass)
        assertFalse(CiGate.decide(combined, sha, "codeguard-rules-v2++sast-1").pass)
        assertTrue(CiGate.decide(combined, sha, "sast-1+codeguard-rules-v2", expected).pass) // старое имя версии принимается
        for (versions in listOf(setOf("sast-1"), setOf("sast-1", "codeguard-rules-v1"),
            combined.rulesVersions + "", setOf(expected))) {
            assertEquals(GateDecision(false, "RULES_VERSION_MISMATCH"),
                CiGate.decide(combined.copy(rulesVersions = versions), sha, expected))
        }
        assertEquals("RULES_VERSION_MISMATCH", CiGate.decide(combined, sha, expected, "codeguard-rules-v1+sast-1").reason)
        val incorrectReport = signedReport.deepCopy().put("rulesVersion", "codeguard-rules-v2+sast-2")
        assertFalse(CiGate.decide(combined.copy(report = incorrectReport), sha, expected).pass)
        assertEquals("CRITICAL_FINDINGS", CiGate.decide(combined.copy(counts = mapOf("CRITICAL" to 1)), sha, expected).reason)
        assertEquals("INCOMPLETE_ANALYSIS", CiGate.decide(combined.copy(coverageStatus = "PARTIAL"), sha, expected).reason)
        assertEquals("COMMIT_MISMATCH", CiGate.decide(combined, "b".repeat(40), expected).reason)
    }
}
