package ru.shopwindow.web

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

@Configuration
class PartnerCors {
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val partners = CorsConfiguration().apply {
            allowedOrigins = listOf("*")
            allowedMethods = listOf("GET", "POST")
            allowCredentials = true
        }
        val widgets = CorsConfiguration().apply {
            allowedOrigins = listOf("*")
            allowedMethods = listOf("GET")
            allowCredentials = false
        }
        val storefront = CorsConfiguration().apply {
            allowedOrigins = listOf("https://app.example.ru")
            allowedMethods = listOf("GET", "POST", "PUT")
            allowCredentials = true
        }
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/partner/**", partners)
            registerCorsConfiguration("/api/widgets/**", widgets)
            registerCorsConfiguration("/api/storefront/**", storefront)
        }
    }

    @Bean
    fun corsFilter(): CorsFilter {
        val c = CorsConfiguration()
        c.addAllowedOriginPattern("*")
        c.addAllowedHeader("Authorization")
        c.allowCredentials = true
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/api/session/**", c)
        return CorsFilter(source)
    }
}
