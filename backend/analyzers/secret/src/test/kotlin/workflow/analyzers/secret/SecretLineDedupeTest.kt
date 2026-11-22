package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SecretLineDedupeTest {
    private fun c(kind: String, path: String, line: Int, vararg extra: Location) =
        SecretCandidate(kind, "v", Location(path, line), listOf(Location(path, line)) + extra)

    @Test
    fun sameLineKeepsHighestPriorityAndMergesEvidence() {
        val usage = Location("B.kt", 9)
        val out = dedupeByLine(listOf(
            c("recoverable-token", "A.kt", 3, usage),
            c("api-key", "A.kt", 3),
        ))
        assertEquals(listOf("api-key"), out.map { it.kind })
        assertTrue(usage in out.single().evidence)
    }

    @Test
    fun configurationTokenLosesToRecoverableToken() {
        val out = dedupeByLine(listOf(c("configuration-token", "A.kt", 5), c("recoverable-token", "A.kt", 5)))
        assertEquals(listOf("recoverable-token"), out.map { it.kind })
    }

    @Test
    fun differentLinesStayApart() {
        val out = dedupeByLine(listOf(c("api-key", "A.kt", 3), c("api-key", "A.kt", 4), c("api-key", "B.kt", 3)))
        assertEquals(3, out.size)
    }

    @Test
    fun customRegexIsKept() {
        val out = dedupeByLine(listOf(c("password", "A.kt", 3), c("custom-regex", "A.kt", 3)))
        assertEquals(setOf("password", "custom-regex"), out.map { it.kind }.toSet())
    }
}
