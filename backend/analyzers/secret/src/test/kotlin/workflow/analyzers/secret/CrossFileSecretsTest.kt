package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class CrossFileSecretsTest {
    @TempDir lateinit var directory: Path

    private fun scan(files: Map<String, String>): List<SecretCandidate> {
        for ((name, text) in files) {
            val file = directory.resolve("src/main/kotlin").resolve(name)
            Files.createDirectories(file.parent)
            Files.writeString(file, text)
        }
        return ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            val result = scanBuiltInSecrets(model)
            val json = secretFindings(model, result.candidates).toString()
            for (raw in listOf("pass123", "dXNlcjpwYXNzMTIz", "N3utr4l-Pw-77x")) assertFalse(raw in json, raw)
            result.candidates
        }
    }

    private fun List<SecretCandidate>.at(file: String) = filter { it.location.path.endsWith(file) }

    private fun List<SecretCandidate>.describe() = map { it.kind + " " + it.location }.toString()

    @Test
    fun base64ConstInObjectUsedInOtherPackage() {
        val found = scan(mapOf(
            "a/Consts.kt" to "package a\nobject Consts {\n    const val A = \"dXNlcjpwYXNzMTIz\"\n    const val LABEL = \"cmVwYWlyLWRlc2s=\"\n}\n",
            "b/Client.kt" to """
                package b
                import a.Consts
                import java.util.Base64
                class Client(val headers: org.springframework.http.HttpHeaders, val log: org.slf4j.Logger) {
                    fun go() {
                        headers.setBasicAuth(String(Base64.getDecoder().decode(Consts.A)))
                        log.info(Consts.LABEL)
                    }
                }
            """.trimIndent(),
        ))
        val consts = found.at("Consts.kt")
        assertEquals(1, consts.size, found.describe())
        assertEquals(3, consts.single().location.line)
        assertTrue(consts.single().evidence.any { it.path.endsWith("Client.kt") }, "evidence includes usage")
    }

    @Test
    fun topLevelConstWithImport() {
        val found = scan(mapOf(
            "a/Consts.kt" to "package a\nconst val A = \"dXNlcjpwYXNzMTIz\"\nconst val LABEL = \"cmVwYWlyLWRlc2s=\"\n",
            "b/Client.kt" to """
                package b
                import a.A
                import a.LABEL
                import java.util.Base64
                class Client(val headers: org.springframework.http.HttpHeaders) {
                    fun go() {
                        headers.setBasicAuth(Base64.getDecoder().decode(A).decodeToString())
                        println(LABEL)
                    }
                }
            """.trimIndent(),
        ))
        val consts = found.at("Consts.kt")
        assertEquals(1, consts.size, found.describe())
        assertEquals(2, consts.single().location.line)
        assertTrue(consts.single().evidence.any { it.path.endsWith("Client.kt") }, "evidence includes usage")
    }

    @Test
    fun neutralNamedConstantUsedAsPassword() {
        val found = scan(mapOf(
            "a/Settings.kt" to "package a\nobject Settings {\n    const val X = \"N3utr4l-Pw-77x\"\n}\n",
            "b/Client.kt" to "package b\nimport a.Settings\nclass C(val h: org.springframework.http.HttpHeaders) {\n    fun go() { h.setBasicAuth(\"admin\", Settings.X) }\n}\n",
        ))
        val s = found.at("Settings.kt")
        assertEquals(1, s.size, found.describe())
        assertEquals("password", s.single().kind)
        assertEquals(3, s.single().location.line)
        assertTrue(s.single().evidence.any { it.path.endsWith("Client.kt") }, "evidence includes usage")
    }

    @Test
    fun neutralNamedConstantUsedAsBearerHeader() {
        val found = scan(mapOf(
            "a/Settings.kt" to "package a\nobject Settings {\n    const val X = \"N3utr4l-Pw-77x\"\n}\n",
            "b/Client.kt" to "package b\nimport a.Settings\nclass C(val b: org.springframework.web.reactive.function.client.WebClient.Builder) {\n    fun go() { b.defaultHeader(\"Authorization\", \"Bearer \" + Settings.X) }\n}\n",
        ))
        val s = found.at("Settings.kt")
        assertEquals(1, s.size, found.describe())
        assertEquals("configuration-token", s.single().kind)
        assertTrue(s.single().evidence.any { it.path.endsWith("Client.kt") }, "evidence includes usage")
    }

    @Test
    fun harmlessConstantUsedInOtherFileIsNotFlagged() {
        val found = scan(mapOf(
            "a/Settings.kt" to "package a\nobject Settings {\n    const val NAME = \"orders-service\"\n}\n",
            "b/Client.kt" to "package b\nimport a.Settings\nclass C(val h: org.springframework.http.HttpHeaders) {\n    fun go() { h.setBasicAuth(\"admin\", System.getenv(\"P\")); println(Settings.NAME) }\n}\n",
        ))
        assertTrue(found.isEmpty(), found.describe())
    }
}
