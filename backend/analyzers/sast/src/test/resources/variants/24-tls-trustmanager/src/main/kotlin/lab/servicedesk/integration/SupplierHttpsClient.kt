package lab.servicedesk.integration

import java.net.URI
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

internal class SupplierHttpsClient {
    fun newConnection(): HttpsURLConnection {
        val url = URI("https://supplier.servicedesk.invalid/catalog").toURL()
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustAll), SecureRandom())
        return (url.openConnection() as HttpsURLConnection).apply {
            connectTimeout = 2_000
            readTimeout = 2_000
            sslSocketFactory = ctx.socketFactory
        }
    }
}
