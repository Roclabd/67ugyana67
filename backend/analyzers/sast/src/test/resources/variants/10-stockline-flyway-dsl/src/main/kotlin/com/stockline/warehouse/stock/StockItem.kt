package com.stockline.warehouse.stock

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository

@Entity
@Table(name = "stock_item")
class StockItem(
    @Id val id: Long = 0,
    val sku: String = "",
    val name: String = "",
    @Column(name = "location_code") val locationCode: String = "",
    val qty: Int = 0,
)

@Entity
@Table(name = "reservation")
class Reservation(
    @Id val id: Long = 0,
    @Column(name = "owner_id") val ownerId: String = "",
    val sku: String = "",
    val qty: Int = 0,
)

interface ReservationRepository : JpaRepository<Reservation, Long> {
    fun findByOwnerId(ownerId: String): List<Reservation>
}
