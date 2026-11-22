package org.ledgerline.reports

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

@Entity
@Table(name = "report")
class ReportEntity(
    @Id val reportId: Long = 0,
    val title: String = "",
    val status: String = "",
    val archived: Boolean = false,
)

interface ReportJpaRepository : JpaRepository<ReportEntity, Long>, JpaSpecificationExecutor<ReportEntity> {
    fun findByTitleContaining(title: String): List<ReportEntity>

    @Query("SELECT r FROM ReportEntity r WHERE r.status = :status AND r.archived = false")
    fun activeByStatus(@Param("status") status: String): List<ReportEntity>
}
