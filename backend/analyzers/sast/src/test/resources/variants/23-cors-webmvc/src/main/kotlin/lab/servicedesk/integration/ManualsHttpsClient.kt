package lab.servicedesk.integration

import java.net.URI
import javax.net.ssl.HttpsURLConnection

internal class ManualsHttpsClient {
    fun newConnection(): HttpsURLConnection =
        URI("https://manuals.servicedesk.invalid/index").toURL().openConnection() as HttpsURLConnection
}
