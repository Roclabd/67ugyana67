package lab.servicedesk.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@Configuration
class RepairSecurity {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            cors { }
            formLogin { }
            authorizeHttpRequests {
                authorize(HttpMethod.GET, "/actuator/health", permitAll)
                authorize(HttpMethod.GET, "/api/catalog/services", permitAll)
                authorize(HttpMethod.GET, "/api/pickup/export", permitAll)
                authorize("/api/pickup/**", hasRole("MECHANIC"))
                authorize("/api/customer/**", authenticated)
                authorize(anyRequest, denyAll)
            }
        }
        return http.build()
    }
}
