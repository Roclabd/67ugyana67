package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class BlindTwoSecretsTest {
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

    @Test
    fun optionalOfNullableFilterOrElseFromEnvironmentIsFallback() {
        val found = kotlin("""
            class Signer(private val env: Environment) {
                fun sign(): ByteArray {
                    val key = Optional.ofNullable(env.getProperty("fleet.unlock.hmac-key"))
                        .filter { it.isNotBlank() }
                        .orElse("unlock-dev-9f3a77c1")
                    return Mac.getInstance("HmacSHA256").also { it.init(SecretKeySpec(key.toByteArray(), "HmacSHA256")) }.doFinal(ByteArray(0))
                }
            }
        """.trimIndent())
        assertEquals(listOf("secret-fallback"), kinds(found, "unlock-dev-9f3a77c1"))
    }

    @Test
    fun orElseThrowAndNonSecretKeyStaySilent() {
        val found = kotlin("""
            class Signer(private val env: Environment) {
                fun a(): String = Optional.ofNullable(env.getProperty("fleet.unlock.hmac-key")).filter { it.isNotBlank() }.orElseThrow()
                fun b(): String = Optional.ofNullable(env.getProperty("fleet.region")).filter { it.isNotBlank() }.orElse("eu-west-1")
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    @Test
    fun configurationPropertiesSecretWithTakeIfElvisLiteralIsFallback() {
        val found = kotlin("""
            class TokenSecrets(private val props: PortalProperties) {
                fun jwt(): String = props.jwtSecret.takeIf { it.isNotBlank() } ?: "gl-hs256-fallback-2023"
                fun report(): String = props.reportSigningSecret.takeIf { it.isNotBlank() } ?: error("must be provided")
                fun region(): String = props.regionName.takeIf { it.isNotBlank() } ?: "eu-west-1"
            }
        """.trimIndent())
        assertEquals(listOf("secret-fallback"), kinds(found, "gl-hs256-fallback-2023"))
        assertTrue(kinds(found, "eu-west-1").isEmpty())
        assertEquals(1, found.size, found.toString())
    }

    @Test
    fun sequentialBuilderAppendsReturnedFromTokenOwnerAreRecoverable() {
        val found = kotlin("""
            object SisSyncToken {
                fun value(): String {
                    val sb = StringBuilder()
                    sb.append("glsync").append('-')
                    sb.append("4f9c").append("a2e1")
                    sb.append("-b7d3-").append("90ce")
                    return sb.toString()
                }
                fun buffered(): String {
                    val sb = StringBuffer("zz")
                    sb.append("q81x")
                    sb.append("-m3pa")
                    return sb.toString()
                }
            }
        """.trimIndent())
        val recoverable = found.filter { it.kind == "recoverable-token" }
        assertEquals(setOf("glsync-4f9ca2e1-b7d3-90ce", "zzq81x-m3pa"), recoverable.map { it.value }.toSet())
        assertEquals(5, recoverable.first { it.value.startsWith("glsync") }.location.line)
    }

    @Test
    fun builderWithRuntimePartOrUnrelatedOwnerIsSilent() {
        val found = kotlin("""
            object SisSyncToken {
                fun value(extra: String): String {
                    val sb = StringBuilder()
                    sb.append("glsync").append('-')
                    sb.append(extra)
                    return sb.toString()
                }
            }
            object Labels {
                fun title(): String {
                    val sb = StringBuilder()
                    sb.append("Report 2024").append(" - ")
                    sb.append("final draft")
                    return sb.toString()
                }
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }

    @Test
    fun methodNamesLookingLikeBase64AreNotRecoverableTokens() {
        val found = kotlin("""
            class StrictTlsBootstrap {
                private val districtSuffix = ".district.example"
                fun install(platform: Verifier) {
                    set { host, session ->
                        host.endsWith(districtSuffix) && platform.verify(host, session)
                    }
                }
            }
        """.trimIndent())
        assertTrue(found.isEmpty(), found.toString())
    }
}
