package ru.velo.service.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class VeloSecurity {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .cors(withDefaults())
        .formLogin(withDefaults())
        .authorizeHttpRequests { rules ->
            rules.requestMatchers(GET, "/api/prices/services").permitAll()
            rules.requestMatchers(GET, "/api/handover/export").permitAll()
            rules.requestMatchers("/api/handover/**").hasRole("MECHANIC")
            rules.requestMatchers("/api/client/**").authenticated()
            rules.anyRequest().denyAll()
        }
        .build()
}
