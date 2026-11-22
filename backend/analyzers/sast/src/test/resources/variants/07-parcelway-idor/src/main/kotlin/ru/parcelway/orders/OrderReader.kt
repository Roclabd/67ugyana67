package ru.parcelway.orders

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class OrderView(val orderId: Long, val customerId: String, val total: Long)

@Repository
class OrderReader(private val jdbc: JdbcTemplate) {
    fun read(orderId: Long): OrderView? = jdbc.query(
        "SELECT order_id, customer_id, total FROM orders WHERE order_id = ?",
        { row, _ -> OrderView(row.getLong(1), row.getString(2), row.getLong(3)) },
        orderId,
    ).firstOrNull()

    fun readOwned(orderId: Long, customerId: String): OrderView? = jdbc.query(
        "SELECT order_id, customer_id, total FROM orders WHERE order_id = ? AND customer_id = ?",
        { row, _ -> OrderView(row.getLong(1), row.getString(2), row.getLong(3)) },
        orderId,
        customerId,
    ).firstOrNull()

    fun listFor(customerId: String): List<OrderView> = jdbc.query(
        "SELECT order_id, customer_id, total FROM orders WHERE customer_id = ? ORDER BY order_id",
        { row, _ -> OrderView(row.getLong(1), row.getString(2), row.getLong(3)) },
        customerId,
    )
}
