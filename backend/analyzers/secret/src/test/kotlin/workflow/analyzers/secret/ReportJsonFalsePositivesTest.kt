package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ReportJsonFalsePositivesTest {
    @TempDir lateinit var directory: Path

    private fun scan(text: String) = run {
        Files.writeString(directory.resolve("report.json"), text)
        ProjectModelBuilder().use { b -> scanBuiltInSecrets(requireNotNull(b.build(directory).model)) }
    }

    @Test
    fun statusWordsAndGitHashesAreNotSecrets() {
        val result = scan(
            "{\n  \"secret\": \"COMPLETE\",\n  \"sast\": \"COMPLETE\",\n  \"token\": \"PARTIAL\",\n" +
                "  \"password\": \"REQUIRED\",\n  \"revision\": \"3f35282787964a7420895c417d00919d35a53a69\",\n" +
                "  \"digest\": \"3f35282787964a7420895c417d00919d35a53a693f35282787964a7420895c41\"\n}\n",
        )
        assertTrue(result.candidates.isEmpty(), result.candidates.toString())
    }

    @Test
    fun plainWeakPasswordInJsonIsStillFound() {
        val result = scan("{\n  \"password\": \"qwerty\"\n}\n")
        assertTrue(result.candidates.isNotEmpty())
    }

    @Test
    fun realMixedTokenIsStillFound() {
        val result = scan("{\n  \"apiToken\": \"a8fK2xQ9mZ7vL4pR1tW6yB3cN5hJ123\"\n}\n")
        assertTrue(result.candidates.isNotEmpty())
    }
}
