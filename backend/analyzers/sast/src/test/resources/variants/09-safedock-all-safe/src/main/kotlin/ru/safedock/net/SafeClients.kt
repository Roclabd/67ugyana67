package ru.safedock.net

import java.net.URI
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import okhttp3.OkHttpClient

internal class SafeClients {
    fun plainConnection(): HttpsURLConnection =
        URI("https://rates.safedock.invalid/daily").toURL().openConnection() as HttpsURLConnection

    fun okHttp(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    fun comparingVerifier(): HttpsURLConnection {
        val conn = URI("https://ledger.safedock.invalid/v1").toURL().openConnection() as HttpsURLConnection
        conn.hostnameVerifier = HostnameVerifier { host, session ->
            host == "ledger.safedock.invalid" && HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session)
        }
        return conn
    }

    fun systemContext(): SSLContext = SSLContext.getDefault()
}
