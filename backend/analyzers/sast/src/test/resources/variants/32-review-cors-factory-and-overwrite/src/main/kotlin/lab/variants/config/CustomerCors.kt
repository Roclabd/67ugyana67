package lab.variants.config

import java.security.Principal
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class CustomerCors {
    private fun defaults(): CorsConfiguration = CorsConfiguration()

    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val customer = defaults()
        customer.allowedOriginPatterns = listOf("*")
        customer.allowCredentials = true
        customer.allowedMethods = listOf("GET")

        val partner = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = true
            allowedOriginPatterns = listOf("https://portal.example.test")
            allowedMethods = listOf("GET")
        }
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/customer/**", customer)
            registerCorsConfiguration("/api/partner/**", partner)
        }
    }

    @Bean
    fun security(http: HttpSecurity): SecurityFilterChain = http
        .cors(withDefaults())
        .formLogin(withDefaults())
        .authorizeHttpRequests { it.anyRequest().authenticated() }
        .build()
}

@RestController
class SummaryController {
    @GetMapping("/api/customer/summary", "/api/partner/summary")
    fun summary(principal: Principal): Map<String, String> = mapOf("customer" to principal.name)
}
