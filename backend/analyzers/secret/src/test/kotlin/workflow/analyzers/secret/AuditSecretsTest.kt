package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/** Аудит: слабые имена ключей, заголовки, сворачивание функций/lazy/кодов, контекст энтропии, текстовые скрипты. */
class AuditSecretsTest {
    @TempDir lateinit var directory: Path

    private fun scan(files: Map<String, String>): List<SecretCandidate> {
        files.forEach { (path, body) ->
            val file = directory.resolve(path)
            Files.createDirectories(file.parent)
            Files.writeString(file, body)
        }
        return ProjectModelBuilder().use { builder ->
            scanBuiltInSecrets(requireNotNull(builder.build(directory).model)).candidates
        }
    }

    private fun kotlin(vararg bodies: String): List<SecretCandidate> =
        scan(bodies.withIndex().associate { (i, b) -> "src/main/kotlin/F$i.kt" to "package p\n\n$b\n" })

    private fun kinds(found: List<SecretCandidate>, value: String) = found.filter { it.value == value }.map { it.kind }

    // ───── S1: имена ─────

    @Test
    fun weakKeyNamesWithSecretValuesAreFound() {
        val found = kotlin("""
            val partnerKey = "pk9Zx3Lm"
            val licenseKey = "LIC-9f3a7c21b8"
            object Cfg {
                const val appKey = "ak91Xq72Lp4"
                val authKey = "Au7kQ2m9Zr8x"
                val clientKey = "cl1ent9KeyZ4q"
                val tokenValue = "tv81Kq72Zp"
                val apiKeyValue = "ak1Val9Zq72"
                val sessionTokenStr = "st91Kq72Zp"
            }
        """.trimIndent())
        assertEquals(listOf("api-key"), kinds(found, "pk9Zx3Lm"))
        assertEquals(listOf("api-key"), kinds(found, "LIC-9f3a7c21b8"))
        assertEquals(listOf("api-key"), kinds(found, "ak91Xq72Lp4"))
        assertEquals(listOf("api-key"), kinds(found, "Au7kQ2m9Zr8x"))
        assertEquals(listOf("api-key"), kinds(found, "cl1ent9KeyZ4q"))
        assertEquals(listOf("configuration-token"), kinds(found, "tv81Kq72Zp"))
        assertEquals(listOf("api-key"), kinds(found, "ak1Val9Zq72"))
        assertEquals(listOf("configuration-token"), kinds(found, "st91Kq72Zp"))
    }

    @Test
    fun pluralKeyListsAreFound() {
        val found = kotlin("""val apiKeys = listOf("kk91Xq72Lp4z", "kk17Zm4Qw8Lp")""")
        assertEquals(listOf("api-key"), kinds(found, "kk91Xq72Lp4z"))
        assertEquals(listOf("api-key"), kinds(found, "kk17Zm4Qw8Lp"))
    }

    @Test
    fun nonSecretKeysAndPlainValuesAreIgnored() {
        val found = kotlin("""
            val cacheKey = "user-profile-v2024"
            val primaryKey = "id9f3a7c21b8"
            val sortKey = "created9At2024"
            val messageKey = "error.not.found9"
            val partitionKey = "tenant9f3a7c21"
            val routingKey = "orders.created9"
            val idempotencyKey = "idem9f3a7c21b8"
            val keyName = "partner9f3a7c21b8"
            val keyPath = "/etc/keys/partner9.pem"
            val partnerKey = "changeme"
            val licenseKey = "short1"
            val appKey = "some readable words 12"
            val authKey = "https://auth.example.test/k9"
            val tokenValue = "your-token-here-9"
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    // ───── S2: заголовки ─────

    @Test
    fun headerNamesClassifyValues() {
        val found = kotlin("""
            fun send(builder: Builder) {
                builder.header("X-Auth", "au91Xq72Lp4z")
                builder.header("X-Partner-Key", "pk91Xq72Lp4z")
                builder.header("X-Client-Token", "ct91Xq72Lp4z")
                builder.header("X-Hub-Secret", "hs91Xq72Lp4z")
                builder.header("Client-Secret", "cs91Xq72Lp4z")
                builder.header("Api-Key", "ak91Xq72Lp4z")
            }
        """.trimIndent())
        assertEquals(listOf("configuration-token"), kinds(found, "au91Xq72Lp4z"))
        assertEquals(listOf("api-key"), kinds(found, "pk91Xq72Lp4z"))
        assertEquals(listOf("configuration-token"), kinds(found, "ct91Xq72Lp4z"))
        assertEquals(listOf("configuration-token"), kinds(found, "hs91Xq72Lp4z"))
        assertEquals(listOf("configuration-token"), kinds(found, "cs91Xq72Lp4z"))
        assertEquals(listOf("api-key"), kinds(found, "ak91Xq72Lp4z"))
    }

    @Test
    fun harmlessHeadersAreIgnored() {
        val found = kotlin("""
            fun send(builder: Builder) {
                builder.header("X-Request-Id", "rq91Xq72Lp4z")
                builder.header("Idempotency-Key", "id91Xq72Lp4z")
                builder.header("X-Idempotency-Key", "ix91Xq72Lp4z")
                builder.header("Content-Type", "application/json")
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    // ───── S3: сворачивание ─────

    @Test
    fun objectFunctionInOtherFileIsFolded() {
        val found = kotlin(
            """
            object Tokens {
                fun partner(): String = "pt91Xq72" + "Lp4zQm18"
            }
            """.trimIndent(),
            """
            fun call(client: Client) {
                client.setBearerAuth(Tokens.partner())
            }
            """.trimIndent(),
        )
        assertEquals(listOf("recoverable-token"), kinds(found, "pt91Xq72Lp4zQm18").distinct())
    }

    @Test
    fun objectFunctionReturnedValueIsFoundEvenWithoutSink() {
        val found = kotlin("""
            object Tokens {
                fun partner(): String = "pt91Xq72" + "Lp4zQm18"
            }
        """.trimIndent())
        assertEquals(listOf("recoverable-token"), kinds(found, "pt91Xq72Lp4zQm18"))
    }

    @Test
    fun lazyDelegateIsFolded() {
        val found = kotlin("""
            val partnerKey by lazy { "lz91Xq72" + "Lp4zQm18" }
        """.trimIndent())
        assertEquals(listOf("recoverable-token"), kinds(found, "lz91Xq72Lp4zQm18"))
    }

    @Test
    fun byteArrayAndCharCodesAreDecoded() {
        val found = kotlin("""
            val partnerKey = String(byteArrayOf(0x62, 0x79, 0x39, 0x31, 0x58, 0x71, 0x37, 0x32, 0x4c, 0x70))
            val licenseKey = intArrayOf(108, 105, 99, 57, 49, 88, 113, 55, 50, 76).map { it.toChar() }.joinToString("")
        """.trimIndent())
        assertEquals(listOf("recoverable-token"), kinds(found, "by91Xq72Lp"))
        assertEquals(listOf("recoverable-token"), kinds(found, "lic91Xq72L"))
    }

    @Test
    fun harmlessFunctionsAndCodesAreIgnored() {
        val found = kotlin("""
            object Labels {
                fun title(): String = "Hello" + " world"
                fun greeting() = "Welcome" + "Back"
            }
            val sizes = intArrayOf(1, 2, 3).map { it.toChar() }.joinToString("")
            val partnerKey = String(byteArrayOf(0x68, 0x69))
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    // ───── S5: контекст энтропии ─────

    @Test
    fun entropyIsClassifiedByContext() {
        val found = scan(mapOf(
            "src/main/resources/application.properties" to """
                http.auth.header=Bearer-ish xK9mQ2vL8pZr4tW7nB3cY6d5
                vendor.licence.blob=xK9mQ2vL8pZr4tW7nB3cY6d6
                client.token.blob=xK9mQ2vL8pZr4tW7nB3cY6d7
                random.blob=xK9mQ2vL8pZr4tW7nB3cY6d8
            """.trimIndent(),
        ))
        assertEquals(listOf("configuration-token"), found.filter { it.value.endsWith("xK9mQ2vL8pZr4tW7nB3cY6d7") }.map { it.kind })
        assertEquals(listOf("api-key"), found.filter { it.value.endsWith("xK9mQ2vL8pZr4tW7nB3cY6d6") }.map { it.kind })
        assertEquals(listOf("high-entropy"), found.filter { it.value.endsWith("xK9mQ2vL8pZr4tW7nB3cY6d8") }.map { it.kind })
    }

    // ───── S4: текстовые файлы вне разбора ─────

    @Test
    fun shellAndHttpFilesAreScanned() {
        val found = scan(mapOf(
            "scripts/deploy.sh" to "#!/bin/sh\nexport PARTNER_API_KEY=pk91Xq72Lp4z\nPASSWORD=hunter2hunter\nTOKEN=\$CI_TOKEN\n",
            "requests/call.http" to "GET http://x.test/a\nX-Api-Key: hk91Xq72Lp4z\nAuthorization: Bearer ab91Xq72Lp4zQ\n",
            "conf/app.conf" to "proxy_set_header X-Partner-Key cf91Xq72Lp4z;\n",
        ))
        assertEquals(listOf("api-key"), kinds(found, "pk91Xq72Lp4z"))
        assertEquals(listOf("password"), kinds(found, "hunter2hunter"))
        assertEquals(listOf("api-key"), kinds(found, "hk91Xq72Lp4z"))
        assertEquals(listOf("configuration-token"), kinds(found, "ab91Xq72Lp4zQ"))
        assertEquals(listOf("api-key"), kinds(found, "cf91Xq72Lp4z"))
        assertEquals(5, found.size, found.toString())
    }

    @Test
    fun textNotesAndReferencesAreIgnored() {
        val found = scan(mapOf(
            "notes.txt" to "Password: required\nToken: see vault\nusage: run the script\nkey=value\n",
            "scripts/run.sh" to "PASSWORD=\${DB_PASSWORD}\nAPI_KEY=\"\$(cat /run/secrets/key)\"\nSECRET=changeme\n",
        ))
        assertTrue(found.isEmpty(), found.toString())
    }
}
