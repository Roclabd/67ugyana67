package lab.servicedesk.config

import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
class RepairCors : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/customer/**")
            .allowedOriginPatterns("*")
            .allowedMethods("GET")
            .allowCredentials(true)
    }
}

@Configuration
class PortalCors : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/pickup/**")
            .allowedOrigins("https://portal.servicedesk.invalid")
            .allowedMethods("GET")
            .allowCredentials(true)
    }
}
