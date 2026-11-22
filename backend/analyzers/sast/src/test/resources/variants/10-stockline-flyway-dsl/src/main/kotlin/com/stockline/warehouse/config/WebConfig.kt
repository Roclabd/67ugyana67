package com.stockline.warehouse.config

import org.springframework.context.annotation.Configuration
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
class WebConfig : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true)
    }
}

@RestController
class HealthController {
    @CrossOrigin(origins = ["*"])
    @GetMapping("/api/health")
    fun health(): Map<String, String> = mapOf("status" to "UP")
}
