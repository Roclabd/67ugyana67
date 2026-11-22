package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import workflow.engine.RunStatus

class RunCompareTest {
    private val json = ObjectMapper()
    private fun f(category: String, cls: String, path: String, line: Int, fp: String, extra: String = "") =
        json.readTree("""{"category":"$category","class":"$cls","path":"$path","line":$line,"fingerprint":"$fp","severity":"HIGH",
            "rule":"r","description":"Секрет в коде"$extra}""")

    @Test fun `unrelated line edit keeps finding unchanged even when fingerprint and line change`() {
        val d = RunComparator.diff(
            listOf(f("SECRET", "password", "src/A.kt", 10, "aaa")),
            listOf(f("SECRET", "password", "src/A.kt", 12, "bbb")),
        )
        assertEquals(1, d.unchanged.size)
        assertTrue(d.added.isEmpty() && d.resolved.isEmpty())
    }

    @Test fun `replacing secret literal with env reference moves finding to resolved`() {
        val d = RunComparator.diff(
            listOf(f("SECRET", "password", "src/A.kt", 10, "aaa"), f("SECRET", "password", "src/A.kt", 30, "ccc")),
            listOf(f("SECRET", "password", "src/A.kt", 31, "ddd")),
        )
        assertEquals(1, d.unchanged.size)
        assertEquals(31, d.unchanged[0].path("line").asInt())
        assertEquals(listOf(10), d.resolved.map { it.path("line").asInt() })
        assertTrue(d.added.isEmpty())
    }

    @Test fun `new finding appears and sca key ignores line but not version`() {
        val sca = { line: Int, fp: String, v: String ->
            f("SCA", "", "pom.xml", line, fp, ""","group":"g","artifact":"a","version":"$v","advisoryId":"CVE-1"""")
        }
        val d = RunComparator.diff(listOf(sca(5, "x", "1.0")), listOf(sca(9, "y", "1.0"), f("SAST", "sql", "B.kt", 3, "z")))
        assertEquals(1, d.unchanged.size)
        assertEquals(listOf("SAST"), d.added.map { it.path("category").asText() })
        val upgraded = RunComparator.diff(listOf(sca(5, "x", "1.0")), listOf(sca(5, "x", "2.0")))
        assertEquals(1, upgraded.resolved.size)
        assertEquals(1, upgraded.added.size)
    }

    private fun side(id: String, rules: String? = "v1", coverage: String? = "COMPLETE", repo: String = "https://x/r",
        status: RunStatus = RunStatus.SUCCESS) =
        CompareSide(id, status, coverage, "repo", repo, "a".repeat(40), "a".repeat(40), "", rules, "w", 1, "2026-01-01T00:00:00Z")

    @Test fun `fix is confirmed only for complete comparable runs`() {
        assertTrue(RunComparator.reasons(side("1"), side("2")).isEmpty())
        assertFalse(RunComparator.reasons(side("1"), side("2", rules = "v2")).isEmpty())
        assertFalse(RunComparator.reasons(side("1"), side("2", coverage = "PARTIAL")).isEmpty())
        assertFalse(RunComparator.reasons(side("1"), side("2", repo = "https://x/other")).isEmpty())
        assertFalse(RunComparator.reasons(side("1"), side("2", status = RunStatus.FAILED)).isEmpty())
        assertFalse(RunComparator.reasons(side("1"), side("1")).isEmpty())
    }

    private fun zip(id: String, hash: String) =
        CompareSide(id, RunStatus.SUCCESS, "COMPLETE", "archive", null, null, hash, "", "v1", "w", 1, "2026-01-01T00:00:00Z")

    @Test fun `two archive versions of one workflow are comparable with a note`() {
        val base = zip("1", "a".repeat(64))
        val head = zip("2", "b".repeat(64))
        assertTrue(RunComparator.reasons(base, head).isEmpty())
        assertEquals(1, RunComparator.notes(base, head).size)
        assertTrue(RunComparator.notes(base, zip("3", "a".repeat(64))).isEmpty())
    }

    @Test fun `workflow project metadata survives json and old payloads still load`() {
        val mapper = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper()
        val wf = workflow.engine.Workflow(name = "n", project = workflow.engine.ProjectMeta("archive", "Demo"))
        val back = mapper.readValue(mapper.writeValueAsString(wf), workflow.engine.Workflow::class.java)
        assertEquals(wf.project, back.project)
        assertNull(mapper.readValue("""{"name":"old","nodes":[],"edges":[]}""", workflow.engine.Workflow::class.java).project)
    }
}
