package lab.variants.repair

import jakarta.servlet.http.HttpSession
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@Configuration
class LookupSecurity {
    @Bean
    fun security(http: HttpSecurity): SecurityFilterChain = http
        .formLogin(withDefaults())
        .authorizeHttpRequests { it.anyRequest().authenticated() }
        .build()
}

@RestController
class TicketLookup(private val jdbc: JdbcTemplate) {
    // Both keys are chosen by the requester; the owner predicate grants no protection.
    @GetMapping("/api/customer/lookup/{ticketId}")
    fun forgedOwner(@PathVariable ticketId: Long, @RequestParam customerId: String): Map<String, Any> =
        jdbc.queryForMap(
            "SELECT * FROM repair_ticket WHERE ticket_id = ? AND customer_id = ?",
            ticketId, customerId,
        )

    @GetMapping("/api/customer/owned-lookup/{ticketId}")
    fun sessionOwner(@PathVariable ticketId: Long, session: HttpSession): Map<String, Any> {
        val context = session.getAttribute("SPRING_SECURITY_CONTEXT")
            as org.springframework.security.core.context.SecurityContext
        return jdbc.queryForMap(
            "SELECT * FROM repair_ticket WHERE ticket_id = ? AND customer_id = ?",
            ticketId, context.authentication.name,
        )
    }
}
