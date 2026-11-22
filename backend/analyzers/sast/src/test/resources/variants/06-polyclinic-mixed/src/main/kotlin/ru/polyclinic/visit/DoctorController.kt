package ru.polyclinic.visit

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class DoctorController(private val jdbc: JdbcTemplate) {
    @GetMapping("/api/doctors")
    fun doctors(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT doctor_id, full_name, speciality FROM doctor ORDER BY full_name")
}
