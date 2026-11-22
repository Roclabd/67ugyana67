package workflow.nodes

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.hc.client5.http.DnsResolver
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.config.ConnectionConfig
import org.apache.hc.client5.http.config.RequestConfig
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.core5.http.ContentType
import org.apache.hc.core5.http.HttpHost
import org.apache.hc.core5.http.HttpEntity
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.util.Timeout
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.URI
import javax.net.SocketFactory

object PublicNetwork {
    fun resolve(host: String): Array<InetAddress> = InetAddress.getAllByName(host).also { addresses ->
        require(addresses.isNotEmpty() && addresses.all(::isPublic)) { "Destination must be public" }
    }

    internal fun isPublic(address: InetAddress): Boolean {
        val bytes = address.address.map { it.toInt() and 255 }
        if (address is Inet4Address) {
            val (a, b, c) = bytes
            return a in 1..223 && a !in setOf(10, 127) &&
                !(a == 100 && b in 64..127) && !(a == 169 && b == 254) &&
                !(a == 172 && b in 16..31) && !(a == 192 && b in setOf(0, 168)) &&
                !(a == 198 && (b in 18..19 || b == 51 && c == 100)) &&
                !(a == 203 && b == 0 && c == 113)
        }
        // Limit IPv6 to global unicast, excluding tunnelling and documentation networks.
        return address is Inet6Address && bytes[0] in 0x20..0x3f &&
            !(bytes[0] == 0x20 && bytes[1] == 0x02) &&
            !(bytes[0] == 0x20 && bytes[1] == 0x01 && (bytes[2] == 0 || bytes[2] == 0x0d && bytes[3] == 0xb8))
    }

    fun post(url: String, body: String, token: String? = null) {
        send(url, StringEntity(body, ContentType.APPLICATION_JSON), token)
    }

    /** Как [post], но возвращает тело ответа (до 1 МБ) и ждёт ответ дольше: для long polling Telegram. */
    fun postForBody(url: String, body: String, responseSeconds: Long): String =
        send(url, StringEntity(body, ContentType.APPLICATION_JSON), null, responseSeconds, true).orEmpty()

    fun sendTelegramDocument(url: String, destination: TelegramDestination, attachment: TelegramAttachment) {
        send(url, telegramDocumentBody(destination, attachment))
    }

    internal fun telegramReportBody(chatId: String, markdown: String): HttpEntity =
        telegramDocumentBody(TelegramDestination(chatId), TelegramAttachment(
            "report.md", "text/markdown", markdown.toByteArray(Charsets.UTF_8),
        ))

    internal fun telegramDocumentBody(destination: TelegramDestination, attachment: TelegramAttachment): HttpEntity {
        val text = ContentType.TEXT_PLAIN.withCharset(Charsets.UTF_8)
        val mime = ContentType.create(attachment.contentType)
        return MultipartEntityBuilder.create()
            .addTextBody("chat_id", destination.chatId, text)
            .apply {
                destination.threadId?.let { addTextBody("message_thread_id", it.toString(), text) }
                if (destination.silent) addTextBody("disable_notification", "true", text)
            }
            .addBinaryBody("document", attachment.content,
                if (mime.mimeType.startsWith("text/")) mime.withCharset(Charsets.UTF_8) else mime,
                attachment.filename)
            .build()
    }

    private fun send(url: String, body: HttpEntity, token: String? = null, responseSeconds: Long = 10, capture: Boolean = false): String? {
        val uri = URI.create(url)
        val host = requireNotNull(uri.host)
        require(uri.scheme == "https" && uri.userInfo == null && uri.fragment == null &&
            uri.port in setOf(-1, 443))
        val proxy = OutboundProxy.current
        val builder = HttpClients.custom()
        val connections = PoolingHttpClientConnectionManagerBuilder.create()
        if (proxy != null) {
            // DNS выполняет прокси: локально хост не разрешаем.
            OutboundProxy.requireExternalHost(host)
            builder.setProxy(HttpHost("http", proxy.host, proxy.port))
        } else {
            val addresses = resolve(host)
            connections.setDnsResolver(object : DnsResolver {
                override fun resolve(requested: String): Array<InetAddress> {
                    require(host.equals(requested, true))
                    return addresses
                }
                override fun resolveCanonicalHostname(requested: String): String = requested
            })
        }
        connections.setDefaultConnectionConfig(ConnectionConfig.custom()
            .setConnectTimeout(Timeout.ofSeconds(5)).setSocketTimeout(Timeout.ofSeconds(responseSeconds)).build())
        return builder.setConnectionManager(connections.build()).disableRedirectHandling().disableAutomaticRetries()
            .disableCookieManagement()
            .setDefaultRequestConfig(RequestConfig.custom().setResponseTimeout(Timeout.ofSeconds(responseSeconds)).build())
            .build().use { client ->
                val request = HttpPost(uri).apply {
                    entity = body
                    if (!token.isNullOrBlank()) setHeader("Authorization", "Bearer $token")
                }
                client.execute(request) { response ->
                    // Тело ответа не попадает в ошибки; для 429 читаем только parameters.retry_after.
                    val retryAfter = if (response.code == 429) runCatching {
                        val raw = response.entity?.content?.use { it.readNBytes(4096) }
                        raw?.let { ObjectMapper().readTree(it).path("parameters").path("retry_after").takeIf { n -> n.isInt }?.asInt() }
                    }.getOrNull() else null
                    val captured = if (capture && response.code in 200..299) {
                        response.entity?.content?.use { String(it.readNBytes(1_000_000), Charsets.UTF_8) }
                    } else null
                    request.cancel()
                    if (response.code !in 200..299) throw DeliveryHttpFailure(response.code, retryAfter)
                    captured
                }
            }
    }

    fun smtpSockets(host: String, port: Int): SocketFactory {
        val pinned = resolve(host).first()
        val target = InetSocketAddress(pinned, port)
        fun connect(socket: Socket): Socket = socket.apply { connect(target, 5000) }
        return object : SocketFactory() {
            override fun createSocket(): Socket = object : Socket() {
                override fun connect(endpoint: SocketAddress, timeout: Int) {
                    val requested = endpoint as InetSocketAddress
                    require(requested.port == port)
                    super.connect(target, timeout)
                }
            }
            override fun createSocket(host: String, port: Int) = connect(createSocket())
            override fun createSocket(address: InetAddress, port: Int) = connect(createSocket())
            override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int) =
                connect(createSocket().apply { bind(InetSocketAddress(local, localPort)) })
            override fun createSocket(address: InetAddress, port: Int, local: InetAddress, localPort: Int) =
                connect(createSocket().apply { bind(InetSocketAddress(local, localPort)) })
        }
    }
}
