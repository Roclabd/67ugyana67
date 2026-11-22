package io.paygate.client

import javax.net.ssl.HttpsURLConnection
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ApacheClientFactory {
    @Bean
    fun legacyApacheClient(): CloseableHttpClient = HttpClients.custom()
        .setMaxConnTotal(20)
        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
        .build()

    @Bean
    fun strictApacheClient(): CloseableHttpClient = HttpClients.custom()
        .setMaxConnTotal(20)
        .useSystemProperties()
        .build()

    init {
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
    }
}
