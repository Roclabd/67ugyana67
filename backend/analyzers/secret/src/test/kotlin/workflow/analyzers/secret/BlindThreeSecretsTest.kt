package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/** Третий слепой корпус: значения по умолчанию в классах настроек, секрет в геттере, R2DBC, ключ из функции, buildString с repeat. */
class BlindThreeSecretsTest {
    @TempDir lateinit var directory: Path

    private fun kotlin(vararg bodies: String): List<SecretCandidate> {
        bodies.forEachIndexed { index, body ->
            val file = directory.resolve("src/main/kotlin/F$index.kt")
            Files.createDirectories(file.parent)
            Files.writeString(file, "package p\n\n$body\n")
        }
        return ProjectModelBuilder().use { builder ->
            scanBuiltInSecrets(requireNotNull(builder.build(directory).model)).candidates
        }
    }

    private fun kinds(found: List<SecretCandidate>, value: String) = found.filter { it.value == value }.map { it.kind }

    // ───── 1. значение по умолчанию в @ConfigurationProperties ─────

    @Test
    fun configurationPropertiesDefaultIsSecretFallback() {
        val found = kotlin("""
            @ConfigurationProperties(prefix = "housekeeping.keycard")
            data class KeycardProperties(
                val encoderUrl: String = "https://keycards.example.test",
                val signingSecret: String = "kc-hmac-dev-secret-90417",
                val issuer: String = "hotelkeep",
            )

            @ConfigurationProperties(prefix = "housekeeping.minibar")
            class MinibarProperties {
                var hmacSecret: String? = null
                var apiKey: String = ""
                var adminPassword: String = "minibar-dev-pw-7731"
            }
        """.trimIndent())
        assertEquals(listOf("secret-fallback"), kinds(found, "kc-hmac-dev-secret-90417"))
        assertEquals(listOf("secret-fallback"), kinds(found, "minibar-dev-pw-7731"))
        assertEquals(2, found.size, found.toString())
    }

    @Test
    fun plainClassDefaultStaysDirectSecret() {
        val found = kotlin("""
            data class Settings(val signingSecret: String = "kc-hmac-dev-secret-90417")
        """.trimIndent())
        assertEquals(listOf("configuration-token"), kinds(found, "kc-hmac-dev-secret-90417"))
    }

    // ───── 2. токен из charArrayOf за геттером ─────

    @Test
    fun charArrayTokenBehindGetterIsRecoverable() {
        val found = kotlin("""
            class PmsAuth {
                private val pmsTokenChars = charArrayOf(
                    'p', 'm', 's', '_', 's', 'v', 'c', '_',
                    'a', '7', 'K', '2', 'x', 'Q', '9', 'd',
                )

                val pmsServiceToken: String
                    get() = pmsTokenChars.concatToString()

                fun status(client: RestClient): String? =
                    client.get().header(HttpHeaders.AUTHORIZATION, "Bearer ${'$'}pmsServiceToken").retrieve().body(String::class.java)
            }
        """.trimIndent())
        assertEquals(listOf("recoverable-token"), kinds(found, "pms_svc_a7K2xQ9d").distinct())
        val line = found.first { it.kind == "recoverable-token" }.location
        assertEquals(4, line.line)
    }

    @Test
    fun getterOverNonSecretNameStaysSilent() {
        val found = kotlin("""
            class Labels {
                private val chars = charArrayOf('p', 'a', 'l', '-', '0', '0', '1')
                val palletLabel: String get() = chars.concatToString()
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    // ───── 3. R2DBC ─────

    @Test
    fun r2dbcPasswordOptionIsPassword() {
        val found = kotlin("""
            import io.r2dbc.spi.ConnectionFactoryOptions
            import io.r2dbc.spi.ConnectionFactoryOptions.PASSWORD

            class Db {
                fun a() = ConnectionFactoryOptions.builder()
                    .option(ConnectionFactoryOptions.DRIVER, "postgresql")
                    .option(ConnectionFactoryOptions.USER, "wms_report")
                    .option(ConnectionFactoryOptions.PASSWORD, "Rp7!wmsReport-2291")
                    .build()

                fun b() = ConnectionFactoryOptions.builder().option(PASSWORD, "Zq4#imported-5518").build()
            }
        """.trimIndent())
        assertEquals(listOf("password"), kinds(found, "Rp7!wmsReport-2291"))
        assertEquals(listOf("password"), kinds(found, "Zq4#imported-5518"))
        assertTrue(kinds(found, "wms_report").isEmpty())
        assertTrue(kinds(found, "postgresql").isEmpty())
    }

    @Test
    fun optionPasswordFromEnvironmentIsSilent() {
        val found = kotlin("""
            import io.r2dbc.spi.ConnectionFactoryOptions
            class Db {
                fun a(pw: String) = ConnectionFactoryOptions.builder()
                    .option(ConnectionFactoryOptions.PASSWORD, pw)
                    .option(ConnectionFactoryOptions.USER, "wms_report")
                    .build()
                fun b() = Options().option(PASSWORD, "not-a-r2dbc-option-1")
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    // ───── 4. ключ из функции в заголовке Authorization ─────

    @Test
    fun functionReturningKeyInAuthorizationHeaderIsApiKey() {
        val found = kotlin("""
            private fun carrierKey() = "ck_live_8fJ2mQxZ47Wb9TrYc1LdVn5HsKa3Pe0G"

            class CarrierApi(private val base: String) {
                fun track(waybill: String): HttpRequest =
                    HttpRequest.newBuilder(URI.create("${'$'}base/track/${'$'}waybill"))
                        .header("Authorization", "Key " + carrierKey())
                        .build()
            }
        """.trimIndent())
        val kinds = found.map { it.kind }
        assertEquals(listOf("api-key"), kinds, found.toString())
        assertEquals(3, found.single().location.line)
    }

    @Test
    fun functionReturningValueUsedOutsideAuthIsSilentOnClass() {
        val found = kotlin("""
            private fun region() = "eu-west-1"
            class Api { fun r(): HttpRequest = HttpRequest.newBuilder().header("X-Region", region()).build() }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    // ───── 5. buildString с repeat, appendLine, trim ─────

    @Test
    fun buildStringWithRepeatAndAppendLineIsRecoverable() {
        val found = kotlin("""
            class DockToken {
                private val dockGateToken: String = buildString {
                    append("dgk")
                    repeat(2) { append("_x9") }
                    appendLine()
                    append("Q4mT7vB2")
                }.trim()

                fun authHeader(): String = "Bearer ${'$'}dockGateToken"

                fun palletLabel(seq: Int): String = buildString {
                    append("PAL-")
                    repeat(3) { append('0') }
                    append(seq)
                }
            }
        """.trimIndent())
        val token = found.filter { it.kind == "recoverable-token" }
        assertEquals(1, token.size, found.toString())
        assertEquals(4, token.single().location.line)
        assertEquals(9, token.single().location.endLine)
        assertTrue(found.none { it.value.startsWith("PAL-") }, found.toString())
    }

    @Test
    fun buildStringWithNonConstantRepeatCountIsSilent() {
        val found = kotlin("""
            class DockToken {
                private val dockGateToken: String = buildString {
                    append("dgk")
                    repeat(count) { append("_x9") }
                }
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }
}
