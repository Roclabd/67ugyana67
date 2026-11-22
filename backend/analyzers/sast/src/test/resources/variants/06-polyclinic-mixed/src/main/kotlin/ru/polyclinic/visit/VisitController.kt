package ru.polyclinic.visit

import java.security.Principal
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/visits")
class VisitController(private val jdbc: JdbcTemplate) {
    @GetMapping("/recent")
    fun recent(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT visit_id, patient_id, doctor_name, visit_date FROM visit ORDER BY visit_date DESC LIMIT 20")

    @GetMapping("/mine")
    fun mine(principal: Principal): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT visit_id, doctor_name, visit_date, note FROM visit WHERE patient_id = ?", principal.name)

    @GetMapping("/{visitId}")
    fun getVisit(@PathVariable visitId: Long): Map<String, Any?> =
        jdbc.queryForMap("SELECT visit_id, patient_id, doctor_name, note FROM visit WHERE visit_id = ?", visitId)

    @GetMapping("/{visitId}/summary")
    fun summary(@PathVariable visitId: Long, principal: Principal): Map<String, Any?> =
        jdbc.queryForMap(
            "SELECT visit_id, doctor_name, visit_date FROM visit WHERE visit_id = ? AND patient_id = ?",
            visitId,
            principal.name,
        )

    @GetMapping("/by-doctor")
    fun byDoctor(@RequestParam doctor: String, principal: Principal): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT visit_id, visit_date FROM visit WHERE doctor_name LIKE '%$doctor%' AND patient_id = '${principal.name}'")

    @GetMapping("/by-date")
    fun byDate(@RequestParam date: String, principal: Principal): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT visit_id, doctor_name FROM visit WHERE visit_date = ? AND patient_id = ?", date, principal.name)
}
