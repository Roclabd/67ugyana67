package lab.servicedesk.integration

import java.net.URI
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

internal class PartnerHttpsClient {
    fun newConnection(): HttpsURLConnection {
        val url = URI("https://partner.servicedesk.invalid/orders").toURL()
        return (url.openConnection() as HttpsURLConnection).apply {
            connectTimeout = 2_000
            hostnameVerifier = HostnameVerifier { hostname, _ -> hostname == "partner.servicedesk.invalid" }
        }
    }
}
