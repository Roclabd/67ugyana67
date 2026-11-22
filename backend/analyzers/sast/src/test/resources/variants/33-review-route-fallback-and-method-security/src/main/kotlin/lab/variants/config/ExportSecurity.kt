package lab.variants.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@Configuration
@EnableMethodSecurity
class ExportSecurity {
    @Bean
    fun security(http: HttpSecurity): SecurityFilterChain = http
        .authorizeHttpRequests { rules ->
            rules.requestMatchers(GET, "/api/admin/export").permitAll()
            rules.anyRequest().permitAll()
        }
        .build()
}

@RestController
class ExportController(private val jdbc: JdbcTemplate) {
    @GetMapping("/api/customer/summary")
    fun summary(): List<Map<String, Any>> = jdbc.queryForList(
        "SELECT * FROM repair_ticket",
    )

    @PreAuthorize("hasRole('MECHANIC')")
    @GetMapping("/api/admin/export")
    fun export(): List<Map<String, Any>> = jdbc.queryForList(
        "SELECT * FROM repair_ticket",
    )
}
