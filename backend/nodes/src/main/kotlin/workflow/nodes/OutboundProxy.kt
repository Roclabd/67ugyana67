package workflow.nodes

import java.net.InetAddress
import java.net.URI

/**
 * Необязательный исходящий HTTP-прокси (APP_OUTBOUND_PROXY, например http://127.0.0.1:10809).
 * Нужен, когда VPN подменяет DNS (адреса 198.18.0.0/15): имя хоста тогда разрешает сам прокси.
 * Пусто — прежнее поведение: локальное разрешение имён и проверка адресов.
 * SMTP через прокси не ходит и работает как раньше.
 */
object OutboundProxy {
    data class Endpoint(val host: String, val port: Int) {
        /** Без учётных данных: безопасно для журнала. */
        override fun toString() = "$host:$port"
        val url: String get() = "http://$host:$port"
    }

    @Volatile
    var current: Endpoint? = null
        private set

    fun configure(raw: String?): Endpoint? {
        current = parse(raw)
        return current
    }

    fun parse(raw: String?): Endpoint? {
        val text = raw?.trim().orEmpty()
        if (text.isEmpty()) return null
        val uri = try { URI.create(text) } catch (_: IllegalArgumentException) { null }
        require(uri != null && uri.scheme == "http" && !uri.host.isNullOrEmpty() && uri.port in 1..65535 &&
            uri.userInfo == null && uri.path.orEmpty().isEmpty() && uri.query == null) {
            "APP_OUTBOUND_PROXY должен иметь вид http://host:port"
        }
        return Endpoint(uri!!.host, uri.port)
    }

    private val numericHost = Regex("^(0x[0-9a-f]+|\\d+)(\\.(0x[0-9a-f]+|\\d+))*$", RegexOption.IGNORE_CASE)
    private val dottedQuad = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    /** Проверка целевого хоста без DNS: имя разрешает прокси, поэтому отсекаем только очевидно внутренние адреса. */
    fun requireExternalHost(rawHost: String) {
        val host = rawHost.trim().removePrefix("[").removeSuffix("]").trimEnd('.').lowercase()
        require(host.isNotEmpty() && host != "localhost" && !host.endsWith(".localhost") &&
            !host.endsWith(".local") && !host.endsWith(".internal")) { "Destination must be public" }
        if (':' in host) {
            require(PublicNetwork.isPublic(InetAddress.getByName(host))) { "Destination must be public" }
        } else if (numericHost.matches(host)) {
            require(dottedQuad.matches(host) && PublicNetwork.isPublic(InetAddress.getByName(host))) {
                "Destination must be public"
            }
        }
    }
}
