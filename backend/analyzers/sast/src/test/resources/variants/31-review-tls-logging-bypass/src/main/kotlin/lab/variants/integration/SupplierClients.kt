package lab.variants.integration

import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SupplierClients {
    fun uncheckedHostname(url: URL): HttpsURLConnection {
        val connection = url.openConnection() as HttpsURLConnection
        connection.hostnameVerifier = HostnameVerifier { host, _ -> println("Connecting to $host"); true }
        return connection
    }

    fun uncheckedCertificate(url: URL): HttpsURLConnection {
        val trust = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw java.security.cert.CertificateException("Client certificates unsupported")
            }
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { println("Received ${chain.size} certificates for $authType") }
        }
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(trust), SecureRandom())
        val connection = url.openConnection() as HttpsURLConnection
        connection.sslSocketFactory = context.socketFactory
        return connection
    }

    fun verified(url: URL): HttpsURLConnection {
        val connection = url.openConnection() as HttpsURLConnection
        connection.hostnameVerifier = HostnameVerifier { host, session -> HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) }
        return connection
    }
}
