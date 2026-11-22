package io.paygate.client

import java.net.URI
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

internal class SettlementClient {
    fun open(): HttpsURLConnection {
        val conn = URI("https://settle.paygate.invalid/v2/batches").toURL().openConnection() as HttpsURLConnection
        conn.connectTimeout = 3_000
        conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
        return conn
    }
}

internal class ReconciliationClient {
    fun open(): HttpsURLConnection {
        val conn = URI("https://recon.paygate.invalid/v1/export").toURL().openConnection() as HttpsURLConnection
        conn.connectTimeout = 3_000
        conn.readTimeout = 10_000
        return conn
    }
}
