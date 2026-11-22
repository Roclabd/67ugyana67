package ru.velo.service.jobs

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class Job(val ticketCode: String, val customerId: String, val workNote: String)

@Repository
class JobReader(private val jdbc: JdbcTemplate) {
    fun fetch(id: Long): Job? = template.query(
        "SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?",
        { row, _ -> Job(row.getString(1), row.getString(2), row.getString(3)) },
        id,
    ).firstOrNull()

    fun openCount(customerId: String): Int = template.queryForObject(
        "SELECT COUNT(*) FROM repair_ticket WHERE customer_id = ?",
        Int::class.javaObjectType,
        customerId,
    ) ?: 0
}
