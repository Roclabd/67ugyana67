package ru.velo.service.jobs

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/client/lookup")
class FrameLookupController(private val jdbc: JdbcTemplate) {
    @GetMapping("/frame")
    fun lookupFrame(@RequestParam q: String): List<String> =
        template.queryForList("SELECT ticket_code FROM repair_ticket WHERE frame_tag = '$q'", String::class.java)

    @GetMapping("/code")
    fun lookupCode(@RequestParam ticketCode: String): List<String> =
        template.queryForList("SELECT ticket_code FROM repair_ticket WHERE ticket_code = ?", String::class.java, ticketCode)
}
