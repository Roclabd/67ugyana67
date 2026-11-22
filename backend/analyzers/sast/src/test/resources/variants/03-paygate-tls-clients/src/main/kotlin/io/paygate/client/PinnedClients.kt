package io.paygate.client

import java.net.URI
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal class PinnedHostClient {
    private val expectedHost = "ledger.paygate.invalid"

    fun open(): HttpsURLConnection {
        val conn = URI("https://ledger.paygate.invalid/v3/entries").toURL().openConnection() as HttpsURLConnection
        conn.hostnameVerifier = HostnameVerifier { host, _ -> host == expectedHost }
        return conn
    }

    fun openDelegating(): HttpsURLConnection {
        val conn = URI("https://ledger.paygate.invalid/v3/balances").toURL().openConnection() as HttpsURLConnection
        conn.hostnameVerifier = HostnameVerifier { host, session ->
            host.endsWith(".paygate.invalid") && HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)
        }
        return conn
    }
}

internal class DelegatingTrustManager(keyStore: KeyStore?) : X509TrustManager {
    private val delegate: X509TrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(keyStore) }
        .trustManagers
        .filterIsInstance<X509TrustManager>()
        .first()

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkClientTrusted(chain, authType)

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
        delegate.checkServerTrusted(chain, authType)

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
}
