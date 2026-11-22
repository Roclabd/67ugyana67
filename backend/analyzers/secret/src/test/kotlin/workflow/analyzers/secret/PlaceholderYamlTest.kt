package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class PlaceholderYamlTest {
    @TempDir lateinit var directory: Path

    private fun scan(name: String, text: String) = run {
        Files.writeString(directory.resolve(name), text)
        ProjectModelBuilder().use { builder -> scanBuiltInSecrets(requireNotNull(builder.build(directory).model)) }
    }

    @Test
    fun secretInSecondYamlDocumentIsFoundWithLine() {
        val result = scan("application.yml", "spring:\n  application:\n    name: demo\n---\nspring:\n  config:\n    activate:\n      on-profile: prod\napp:\n  password: Zq9!vR7#kLm2xP\n")
        val hit = result.candidates.single { it.kind == "password" }
        assertEquals(10, hit.location.line)
    }

    @Test
    fun fakeBodyPrivateKeyIsFoundButPlaceholderBodyIsNot() {
        Files.writeString(directory.resolve("dummy.key"), "-----BEGIN PRIVATE KEY-----\nTHIS-IS-A-FAKE-TRAINING-MARKER\n-----END PRIVATE KEY-----\n")
        Files.writeString(directory.resolve("doc.pem"), "-----BEGIN PRIVATE KEY-----\n<your private key here>\n-----END PRIVATE KEY-----\n")
        val result = scan("application.yml", "a: b\n")
        assertEquals(listOf("dummy.key"), result.candidates.map { it.location.path })
    }

    @Test
    fun maskedPlaceholdersAreNotSecrets() {
        val values = listOf("****", "******", "<redacted>", "redacted", "REDACTED", "xxx", "changeme", "\${DB_PASS}", "<your-token>")
        val yaml = values.mapIndexed { i, v -> "k$i:\n  password: '$v'\n" }.joinToString("")
        val result = scan("application.yml", yaml)
        assertTrue(result.candidates.isEmpty(), result.candidates.toString())
        assertFalse(isPlaceholder("Zq9!vR7#kLm2xP"))
    }
}
