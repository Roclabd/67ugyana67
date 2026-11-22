package ru.shopwindow.web

import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
class MvcCorsConfig : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/orders/**")
            .allowedOriginPatterns("*")
            .allowedMethods("GET", "POST")
            .allowCredentials(true)

        registry.addMapping("/api/prices/**")
            .allowedOrigins("*")
            .allowedMethods("GET")

        registry.addMapping("/api/profile/**")
            .allowedOrigins("https://app.example.ru")
            .allowedMethods("GET", "PUT")
            .allowCredentials(true)
    }
}
