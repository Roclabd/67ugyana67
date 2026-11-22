package ru.velo.service.handover

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class HandoverExportController(private val jdbc: JdbcTemplate) {
    @GetMapping("/api/handover/export")
    fun exportAll(): List<Map<String, Any?>> = template.queryForList(
        """SELECT r.ticket_code, r.customer_id, p.counter_note
           FROM pickup_slot p JOIN repair_ticket r ON p.ticket_id = r.ticket_id
           ORDER BY r.ticket_id""",
    )
}
