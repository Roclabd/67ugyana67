package lab.servicedesk.repair

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table

@Entity
@Table(name = "repair_ticket")
class RepairTicketEntity(
    @Id
    @Column(name = "ticket_id")
    val ticketId: Long = 0,
    @Column(name = "ticket_code")
    val ticketCode: String = "",
    @Column(name = "customer_id")
    val customerId: String = "",
    @Column(name = "work_note")
    val workNote: String = "",
)
