package lab.servicedesk.repair

import org.springframework.stereotype.Repository

data class RepairTicket(val ticketCode: String, val customerId: String, val workNote: String)

@Repository
class RepairTicketReader(private val repository: RepairTicketRepository) {
    fun read(ticketId: Long): RepairTicket? =
        repository.findById(ticketId)
            .map { RepairTicket(it.ticketCode, it.customerId, it.workNote) }
            .orElse(null)

    fun countForCustomer(customerId: String): Int = repository.countByCustomerId(customerId).toInt()
}
