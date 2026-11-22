package workflow.app

import org.apache.commons.logging.LogFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import workflow.nodes.OutboundProxy

/** APP_OUTBOUND_PROXY (окружение или .env): http://host:port. Пусто - прямые запросы. */
@Configuration(proxyBeanMethods = false)
class OutboundProxyConfig(@Value("\${APP_OUTBOUND_PROXY:}") raw: String) {
    init {
        OutboundProxy.configure(raw)?.let {
            LogFactory.getLog(OutboundProxyConfig::class.java).info("Исходящие запросы через прокси $it")
        }
    }
}
