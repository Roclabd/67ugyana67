package ru.cashbox.portal.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
class PortalSecurity(private val jwtAuthFilter: JwtAuthFilter) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .csrf { it.disable() }
        .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter::class.java)
        .authorizeHttpRequests { rules ->
            rules.requestMatchers("/api/auth/**").permitAll()
            rules.requestMatchers("/api/accounts/export").permitAll()
            rules.requestMatchers("/api/accounts/**").hasAnyRole("CLIENT", "MANAGER")
            rules.anyRequest().authenticated()
        }
        .build()
}
