package com.stockline.warehouse.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@Configuration
class WarehouseSecurity {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            httpBasic { }
            authorizeHttpRequests {
                authorize("/api/health", permitAll)
                authorize("/api/stock/summary", permitAll)
                authorize("/api/stock/**", hasRole("STOREKEEPER"))
                authorize("/api/reservations/**", authenticated)
                authorize(anyRequest, denyAll)
            }
        }
        return http.build()
    }
}
