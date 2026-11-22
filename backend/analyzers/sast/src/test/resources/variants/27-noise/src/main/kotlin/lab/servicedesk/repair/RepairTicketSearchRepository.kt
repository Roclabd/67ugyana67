package lab.servicedesk.repair

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor

interface RepairTicketSearchRepository :
    JpaRepository<RepairTicketEntity, Long>,
    JpaSpecificationExecutor<RepairTicketEntity>
