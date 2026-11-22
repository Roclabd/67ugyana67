package lab.servicedesk.repair

import org.springframework.data.jpa.repository.JpaRepository

interface RepairTicketRepository : JpaRepository<RepairTicketEntity, Long> {
    fun countByCustomerId(customerId: String): Long

    fun findByTicketIdAndCustomerId(ticketId: Long, customerId: String): RepairTicketEntity?
}
