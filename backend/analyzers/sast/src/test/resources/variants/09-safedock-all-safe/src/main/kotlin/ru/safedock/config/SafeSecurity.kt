package ru.safedock.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableMethodSecurity
class SafeSecurity {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .cors(withDefaults())
        .httpBasic(withDefaults())
        .authorizeHttpRequests { rules ->
            rules.requestMatchers("/actuator/health").permitAll()
            rules.requestMatchers(HttpMethod.GET, "/api/public/rates").permitAll()
            rules.requestMatchers("/api/admin/**").hasRole("ADMIN")
            rules.requestMatchers("/api/notes/**").authenticated()
            rules.anyRequest().denyAll()
        }
        .build()
}
