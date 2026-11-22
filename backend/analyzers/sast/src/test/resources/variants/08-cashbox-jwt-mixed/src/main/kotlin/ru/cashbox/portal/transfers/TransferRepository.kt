package ru.cashbox.portal.transfers

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

@Repository
class TransferRepository(private val jdbc: JdbcTemplate) {
    fun byDescription(description: String): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT transfer_id, amount, description FROM transfer WHERE description LIKE '%" + description + "%'")

    fun atLeast(min: Long): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT transfer_id, amount, description FROM transfer WHERE amount >= $min")
}
