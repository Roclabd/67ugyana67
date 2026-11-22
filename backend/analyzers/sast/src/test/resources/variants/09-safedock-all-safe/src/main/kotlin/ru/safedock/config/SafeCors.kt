package ru.safedock.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class SafeCors {
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val app = CorsConfiguration().apply {
            allowedOrigins = listOf("https://app.example.ru")
            allowedMethods = listOf("GET", "POST")
            allowCredentials = true
        }
        val publicRates = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowedMethods = listOf("GET")
        }
        val c = CorsConfiguration()
        c.addAllowedOriginPattern("*")
        c.allowCredentials = false
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/notes/**", app)
            registerCorsConfiguration("/api/public/**", publicRates)
            registerCorsConfiguration("/api/embed/**", c)
        }
    }
}

@RestController
class RatesController {
    @CrossOrigin(origins = ["https://app.example.ru"], allowCredentials = "true")
    @GetMapping("/api/public/rates")
    fun rates(): Map<String, Double> = mapOf("USD" to 91.5, "EUR" to 99.2)
}
