package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.net.URI
import java.util.Collections

@Component
class AllowedHostFilter(
    private val json: ObjectMapper,
    @Value("\${APP_ALLOWED_HOSTS:localhost,127.0.0.1,[::1]}") configuredHosts: String,
) : OncePerRequestFilter() {
    private val allowed = configuredHosts.split(',').map { name ->
        requireNotNull(parseHost(name.trim(), allowPort = false)) { "Invalid host in APP_ALLOWED_HOSTS" }
    }.toSet()

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val headers = Collections.list(request.getHeaders("Host"))
        val authority = when (headers.size) {
            0 -> request.serverName
            1 -> headers.single()
            else -> ""
        }
        if (parseHost(authority, allowPort = true) in allowed) {
            chain.doFilter(request, response)
            return
        }
        response.status = HttpServletResponse.SC_BAD_REQUEST
        response.contentType = "application/json;charset=UTF-8"
        json.writeValue(response.outputStream, mapOf("code" to "HOST_NOT_ALLOWED", "message" to "Этот адрес сервера не разрешён."))
    }

    private fun parseHost(authority: String, allowPort: Boolean): String? = runCatching {
        val uri = URI("http://$authority")
        require(uri.userInfo == null && uri.rawPath.isNullOrEmpty() && uri.rawQuery == null && uri.rawFragment == null)
        require(uri.port == -1 || (allowPort && uri.port in 1..65535))
        requireNotNull(uri.host).removeSurrounding("[", "]").trimEnd('.').lowercase()
    }.getOrNull()
}
