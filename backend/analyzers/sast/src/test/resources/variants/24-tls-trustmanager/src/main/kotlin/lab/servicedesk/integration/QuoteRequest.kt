package lab.servicedesk.integration

import java.net.URI
import java.net.http.HttpRequest

internal class QuoteRequest {
    private val pricingApiKey = "placeholder-value"

    fun build(): HttpRequest = HttpRequest.newBuilder(URI("https://parts.servicedesk.invalid/pricing"))
        .header("X-Api-Key", pricingApiKey)
        .GET()
        .build()
}
