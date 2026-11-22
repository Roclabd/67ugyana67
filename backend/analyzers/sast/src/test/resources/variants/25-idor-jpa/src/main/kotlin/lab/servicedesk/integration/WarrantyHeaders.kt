package lab.servicedesk.integration

import org.springframework.http.HttpHeaders

internal class WarrantyHeaders {
    fun build(): HttpHeaders {
        val series = "placeholder-value"
        val grant = "placeholder-part"
        val access = series + grant
        return HttpHeaders().apply { setBearerAuth(access) }
    }
}
