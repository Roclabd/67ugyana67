package lab.servicedesk.repair

import org.springframework.data.jpa.domain.Specification
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/customer/spec-search")
class RepairSpecSearchController(private val repository: RepairTicketSearchRepository) {
    @GetMapping("/code")
    fun byCode(@RequestParam ticketCode: String): List<RepairTicketEntity> =
        repository.findAll(
            Specification { root, _, cb -> cb.equal(root.get<String>("ticketCode"), ticketCode) },
        )
}
