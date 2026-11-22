package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastResult
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Один небезопасный TLS-клиент даёт одну находку; разные клиенты — разные. */
class TlsDedupeTest {
    private fun analyze(path: String, text: String): SastResult {
        val (src, errs) = SastProjectLoader.parseKotlin(path, text.trimIndent())
        assertTrue(errs.isEmpty(), "$errs")
        return SastAnalyzer().analyze(SastProject(listOf(src), emptyMap(), errs))
    }

    private fun SastResult.tls() = findings.filter { it.sastClass == "tls-verification" }

    @Test
    fun okHttpTrustAllAndHostnameVerifierMerge() {
        val r = analyze("Client.kt", """
            object TrustAll : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
            class Api {
                fun client(ctx: SSLContext): OkHttpClient =
                    OkHttpClient.Builder()
                        .sslSocketFactory(ctx.socketFactory, TrustAll)
                        .hostnameVerifier { _, _ -> true }
                        .build()
            }
        """).tls()
        assertEquals(1, r.size, r.toString())
        assertTrue(r.single().evidence.size >= 2, "evidence: ${r.single().evidence}")
    }

    @Test
    fun apacheTrustAllAndNoopMerge() {
        val r = analyze("Apache.kt", """
            class Api {
                fun client() {
                    val ctx = SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build()
                    HttpClients.custom().setSSLContext(ctx).setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build()
                }
            }
        """).tls()
        assertEquals(1, r.size, r.toString())
        assertEquals(2, r.single().evidence.size)
    }

    @Test
    fun twoClientsInTwoFunctionsStayTwo() {
        val r = analyze("Two.kt", """
            class Api {
                fun a() = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }.build()
                fun b() = HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build()
            }
        """).tls()
        assertEquals(2, r.size, r.toString())
    }
}
