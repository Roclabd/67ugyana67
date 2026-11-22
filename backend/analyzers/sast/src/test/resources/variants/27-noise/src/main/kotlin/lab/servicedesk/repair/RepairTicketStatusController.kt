package lab.servicedesk.repair

import java.security.Principal
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/customer")
class RepairTicketStatusController(private val jdbc: JdbcTemplate) {
    @GetMapping("/tickets/{ticketId}/status")
    fun status(@PathVariable ticketId: Long, principal: Principal): List<String> = jdbc.queryForList(
        "SELECT work_note FROM repair_ticket WHERE ticket_id = ? AND customer_id = ?",
        String::class.java,
        ticketId,
        principal.name,
    )
}
