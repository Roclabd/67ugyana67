package lab.variants.config

import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
class PatternCors : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/subdomains/**")
            .allowedOriginPatterns("https://*.example.invalid")
            .allowCredentials(true)

        registry.addMapping("/api/exact/**")
            .allowedOrigins("https://portal.example.invalid")
            .allowCredentials(true)

        registry.addMapping("/api/dev/**")
            .allowedOriginPatterns("http://localhost:*")
            .allowCredentials(true)
    }
}
