package lab.variants.repair

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.servlet.http.HttpSession
import java.security.Principal
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

@Entity
@Table(name = "repair_ticket")
data class RepairTicket(@Id val ticketId: Long, val customerId: String, val workNote: String)

interface TicketRepository : JpaRepository<RepairTicket, Long>

@Configuration
class TicketSecurity {
    @Bean
    fun security(http: HttpSecurity): SecurityFilterChain = http
        .formLogin(withDefaults())
        .authorizeHttpRequests { it.anyRequest().authenticated() }
        .build()
}

@RestController
class TicketController(private val tickets: TicketRepository, private val jdbc: JdbcTemplate) {
    // Logging an authenticated identity does not constrain which ticket is returned.
    @GetMapping("/api/customer/tickets/{ticketId}")
    fun auditOnly(@PathVariable ticketId: Long, principal: Principal): RepairTicket {
        println("Customer ${principal.name} opened ticket $ticketId")
        return tickets.findById(ticketId).orElseThrow()
    }

    // The session identity comes from Spring Security's authenticated session.
    // A foreign row never leaves this method, even though SQL loads it first.
    @GetMapping("/api/customer/checked-tickets/{ticketId}")
    fun checked(@PathVariable ticketId: Long, session: HttpSession): Map<String, Any> {
        val currentCustomer = session.getAttribute("SPRING_SECURITY_CONTEXT")
            as org.springframework.security.core.context.SecurityContext
        val row = jdbc.queryForMap(
            "SELECT * FROM repair_ticket WHERE ticket_id = ?", ticketId,
        )
        require(row["customer_id"] == currentCustomer.authentication.name)
        return row
    }
}
