package workflow.app

import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.Resource
import org.springframework.http.MediaType
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.web.servlet.resource.PathResourceResolver
import org.springframework.web.servlet.resource.ResourceResolverChain

/**
 * Прямые ссылки на экраны интерфейса (BrowserRouter) в собранном JAR: /settings, /projects, /runs/{id}/report и т.д.
 * Если статического файла нет, а браузер просит HTML, отдаём index.html. Остальное остаётся настоящим 404:
 * все пути под /api (API, SSE, скачивания отчётов), пути с расширением (/assets/missing.js) и не-HTML запросы.
 */
@Configuration(proxyBeanMethods = false)
class SpaFallback : WebMvcConfigurer {
    override fun addResourceHandlers(registry: ResourceHandlerRegistry) {
        registry.addResourceHandler("/**")
            .addResourceLocations("classpath:/static/")
            .resourceChain(false)
            .addResolver(SpaResolver)
    }

    internal object SpaResolver : PathResourceResolver() {
        override fun resolveResourceInternal(
            request: HttpServletRequest?,
            requestPath: String,
            locations: MutableList<out Resource>,
            chain: ResourceResolverChain,
        ): Resource? {
            super.resolveResourceInternal(request, requestPath, locations, chain)?.let { return it }
            if (request == null || !isRoute(request.method, requestPath, request.getHeaders("Accept").toList())) return null
            return locations.firstNotNullOfOrNull { location ->
                location.createRelative("index.html").takeIf { it.isReadable }
            }
        }

        internal fun isRoute(method: String, path: String, accept: List<String>): Boolean {
            if (method != "GET" && method != "HEAD") return false
            val clean = path.trim('/')
            if (clean == "api" || clean.startsWith("api/")) return false
            if ('.' in clean.substringAfterLast('/')) return false
            return accept.flatMap { runCatching { MediaType.parseMediaTypes(it) }.getOrDefault(emptyList()) }
                .any { it.type == "text" && it.subtype == "html" || it.type == "application" && it.subtype == "xhtml+xml" }
        }
    }
}
