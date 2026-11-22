package ru.velo.service.integration

import java.net.URI
import java.net.http.HttpRequest

internal class DepotStatusClient {
    fun request(): HttpRequest {
        val access = System.getenv("DEPOT_STATUS_TOKEN") ?: "placeholder-value"
        return HttpRequest.newBuilder(URI("https://depot.servicedesk.invalid/status"))
            .header("Authorization", "Bearer $access")
            .GET()
            .build()
    }
}
