package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class EntropySecretsTest {
    @TempDir lateinit var directory: Path

    private val random = "xK9mQ2vL8pZr4tW7nB3cY6dF"
    private val hex40 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"

    /** Сканирует один файл в src/main и возвращает виды найденных кандидатов. */
    private fun kinds(name: String, text: String): List<String> {
        val file = directory.resolve("src/main").resolve(name)
        Files.createDirectories(file.parent)
        Files.writeString(file, text)
        return ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            scanBuiltInSecrets(model).candidates.map { it.kind }
        }
    }

    private fun flagged(name: String, text: String) = "high-entropy" in kinds(name, text)

    @Test
    fun detectsRandomStringsUnderNeutralNames() {
        assertTrue(flagged("kotlin/A.kt", "val abc = \"$random\"\n"))
        assertTrue(flagged("resources/application.yml", "custom:\n  zzz: $random\n"))
        assertTrue(flagged("resources/app.properties", "zzz=$random\n"))
        assertTrue(flagged("kotlin/J.kt", "val q = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abcDEF123ghiJKL456\"\n"))
        assertTrue(flagged("kotlin/H.kt", "val q = \"$hex40$hex40\"\n"))
    }

    @Test
    fun ignoresOrdinaryStrings() {
        val samples = listOf(
            "val id = \"123e4567-e89b-12d3-a456-426614174000\"",
            "val sum = \"$hex40$hex40\" // sha256 checksum",
            "package workflow.analyzers.secret.internal2024",
            "class VeryLongDescriptiveClassName2Impl",
            "implementation(\"org.springframework.boot:spring-boot-starter-web\")",
            "val sql = \"SELECT id, name FROM customers WHERE created_at > now() ORDER BY id\"",
            "val u = \"https://example.com/api/v1/repair-orders/list\"",
            "val p = \"changeme_changeme_changeme\"",
            "val m = \"MAX_RETRY_COUNT_2024\"",
        )
        for (sample in samples) assertFalse(flagged("kotlin/N.kt", sample + "\n"), sample)
    }

    private fun recoverable(name: String, text: String) = "recoverable-token" in kinds(name, text)

    @Test
    fun detectsShortBase64Secrets() {
        assertTrue(recoverable("kotlin/B.kt", "val abc = \"cGFzc3dvcmQxMjM=\"\n"))
        assertTrue(recoverable("kotlin/B2.kt", "val b = \"cGFzc3dvcmQ=\"\n"))
        assertTrue(recoverable("resources/application.yml", "app:\n  p: U3VwM3JTM2NyZXQh\n"))
        assertTrue(recoverable("resources/app.properties", "zzz=U3VwM3JTM2NyZXQh\n"))
        // Одна строка — не два вида: энтропийный кандидат не дублирует расшифрованный.
        assertFalse(flagged("kotlin/B3.kt", "val abc = \"cGFzc3dvcmQxMjM=\"\n"))
    }

    @Test
    fun ignoresNonSecretBase64Lookalikes() {
        val samples = listOf(
            "val a = \"settings\"",
            "val a = \"Controller\"",
            "val a = \"RepairOrders\"",
            "val a = \"cGFzcw==\"",
            "val a = \"cHVibGljLWxhYmVs\"",
            "val a = \"/9j/4AAQSkZJRg==\"",
            "val a = \"3q2+7w==\"",
            "val u = \"https://example.com/?t=cGFzc3dvcmQxMjM=\"",
        )
        for (sample in samples) assertFalse(recoverable("kotlin/N2.kt", sample + "\n"), sample)
    }

    @Test
    fun base64OnNamedRuleLineIsNotDuplicated() {
        val found = kinds("kotlin/P2.kt", "val password = \"$random\" // cGFzc3dvcmQxMjM=\n")
        assertEquals(0, found.count { it == "high-entropy" || it == "recoverable-token" }, found.toString())
    }

    @Test
    fun namedRuleLineIsNotDuplicated() {
        val found = kinds("kotlin/P.kt", "val password = \"$random\"\n")
        assertTrue(found.isNotEmpty())
        assertEquals(0, found.count { it == "high-entropy" }, found.toString())
    }

    @Test
    fun pemBodyIsLeftToPemRule() {
        val body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
        val found = kinds("resources/key.pem", "-----BEGIN PRIVATE KEY-----\n$body-----END PRIVATE KEY-----\n")
        assertFalse("high-entropy" in found, found.toString())
    }
}
