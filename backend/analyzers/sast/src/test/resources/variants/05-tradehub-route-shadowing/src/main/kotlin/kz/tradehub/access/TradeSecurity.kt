package kz.tradehub.access

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class TradeSecurity {
    @Bean
    @Order(2)
    fun apiChain(http: HttpSecurity): SecurityFilterChain = http
        .securityMatcher("/api/**", "/actuator/**")
        .httpBasic(withDefaults())
        .authorizeHttpRequests { rules ->
            rules.requestMatchers("/actuator/health").permitAll()
            rules.requestMatchers(HttpMethod.GET, "/api/catalog/**").permitAll()
            rules.requestMatchers("/api/admin/export").permitAll()
            rules.requestMatchers("/api/admin/**").hasRole("ADMIN")
            rules.requestMatchers("/api/account/**").authenticated()
            rules.anyRequest().denyAll()
        }
        .build()

    @Bean
    @Order(1)
    fun internalChain(http: HttpSecurity): SecurityFilterChain = http
        .securityMatcher("/internal/**")
        .httpBasic(withDefaults())
        .authorizeHttpRequests { rules ->
            rules.requestMatchers("/internal/**").authenticated()
            rules.requestMatchers("/internal/ops/**").hasRole("OPS")
            rules.anyRequest().denyAll()
        }
        .build()
}
