package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class FormatAndBuilderSecretsTest {
    @TempDir lateinit var directory: Path

    private fun scan(body: String, header: String = ""): List<SecretCandidate> {
        val file = directory.resolve("src/main/kotlin/Client.kt")
        Files.createDirectories(file.parent)
        Files.writeString(file, "import org.springframework.http.HttpHeaders\n$header\nclass Client {\n    fun go(): HttpHeaders {\n$body\n    }\n}\n")
        return ProjectModelBuilder().use { builder ->
            scanBuiltInSecrets(requireNotNull(builder.build(directory).model)).candidates
        }
    }

    private fun bearer(candidates: List<SecretCandidate>) = candidates.filter { it.value == "lbl_Gm3TqW7z" }

    private fun headersBody(credential: String) = """
        val prefix = "lbl_Gm3Tq"
        val body = "W7z"
        val credential = $credential
        return HttpHeaders().also { it.setBearerAuth(credential) }
    """.trimIndent()

    @Test
    fun kotlinFormatIsFolded() {
        assertEquals(1, bearer(scan(headersBody("\"%s%s\".format(prefix, body)"))).size)
    }

    @Test
    fun javaStringFormatIsFolded() {
        assertEquals(1, bearer(scan(headersBody("String.format(\"%s%s\", prefix, body)"))).size)
    }

    @Test
    fun formattedIsFolded() {
        assertEquals(1, bearer(scan(headersBody("\"%s%s\".formatted(prefix, body)"))).size)
    }

    @Test
    fun positionalFormatIsFolded() {
        val d = "$"
        assertEquals(1, bearer(scan(headersBody("\"%1\\${d}s%2\\${d}s\".format(prefix, body)"))).size)
        assertEquals(1, bearer(scan(headersBody("\"%2\\${d}s%1\\${d}s\".format(body, prefix)"))).size)
    }

    @Test
    fun unsupportedOrBrokenFormatIsNotFolded() {
        assertTrue(bearer(scan(headersBody("\"%s%s%s\".format(prefix, body)"))).isEmpty())
        assertTrue(bearer(scan(headersBody("\"%d%s\".format(1, body)"))).isEmpty())
        assertTrue(bearer(scan(headersBody("\"%s\".format(System.getenv(\"X\"))"))).isEmpty())
    }

    @Test
    fun stringBuilderChainIsFolded() {
        val body = """
            val b = StringBuilder().append("lbl_Gm3Tq").append("W7z").toString()
            return HttpHeaders().also { it.setBearerAuth(b) }
        """.trimIndent()
        assertEquals(1, bearer(scan(body)).size)
    }

    @Test
    fun stringBuilderWithInitAndBufferAndValBuilder() {
        val init = """
            val b = StringBuilder("lbl_Gm3Tq").append("W7z").toString()
            return HttpHeaders().also { it.setBearerAuth(b) }
        """.trimIndent()
        assertEquals(1, bearer(scan(init)).size)
        val buffer = """
            val b = StringBuffer().append("lbl_Gm3Tq").append("W7z").toString()
            return HttpHeaders().also { it.setBearerAuth(b) }
        """.trimIndent()
        assertEquals(1, bearer(scan(buffer)).size)
        val viaVal = """
            val sb = StringBuilder("lbl_Gm3Tq").append("W7z")
            val b = sb.toString()
            return HttpHeaders().also { it.setBearerAuth(b) }
        """.trimIndent()
        assertEquals(1, bearer(scan(viaVal)).size)
    }

    @Test
    fun builderWithRuntimePartIsNotFolded() {
        val body = """
            val b = StringBuilder("lbl_Gm3Tq").append(System.getenv("TAIL")).toString()
            return HttpHeaders().also { it.setBearerAuth(b) }
        """.trimIndent()
        assertTrue(bearer(scan(body)).isEmpty())
    }

    @Test
    fun passWordIsPasswordButSimilarWordsAreNot() {
        for (n in listOf("dbPass", "adminPass", "pass", "DB_PASS")) assertEquals("password", secretKind(n), n)
        for (n in listOf("bypass", "passport", "passenger", "compass", "passive", "passthrough", "passThrough", "passCount")) assertNull(secretKind(n), n)
    }

    @Test
    fun dbPassConstantIsReported() {
        val found = scan("return HttpHeaders()", "internal class Settings {\n    private val dbPass = \"Shf_9qLx2Rv7mKt4Wz\"\n}")
        assertTrue(found.any { it.kind == "password" }, found.toString())
    }
}
