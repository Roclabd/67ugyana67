package org.ledgerline.reports

import org.springframework.stereotype.Service

@Service
class ReportService(
    private val repository: ReportRepository,
    private val jpa: ReportJpaRepository,
) {
    fun search(filter: ReportFilter) = repository.findByStatusNative(filter.status)

    fun titleSearch(q: String) = repository.titleLike(q)

    fun archive(before: String) = repository.markArchived(before)

    fun listByState(state: String) = repository.reportIdsByState(state)

    fun safeSearch(status: String): List<ReportEntity> =
        jpa.findAll(ReportSpecs.hasStatus(status)) + repository.findByStatusSafe(status) + jpa.activeByStatus(status)
}
