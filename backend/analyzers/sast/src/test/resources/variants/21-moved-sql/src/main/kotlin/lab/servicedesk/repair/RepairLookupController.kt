package lab.servicedesk.repair

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/customer/search")
class RepairLookupController(
    private val service: RepairLookupService,
    private val jdbc: JdbcTemplate,
) {
    @GetMapping("/frame")
    fun findByFrameTag(@RequestParam frameTag: String): List<String> =
        service.find(frameTag)

    @GetMapping("/code")
    fun findByTicketCode(@RequestParam ticketCode: String): List<String> =
        jdbc.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, ticketCode)
}
