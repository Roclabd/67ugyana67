package org.ledgerline.reports

import org.springframework.data.jpa.domain.Specification

object ReportSpecs {
    fun hasStatus(status: String): Specification<ReportEntity> =
        Specification { root, _, cb -> cb.equal(root.get<String>("status"), status) }

    fun titleLike(fragment: String): Specification<ReportEntity> =
        Specification { root, _, cb -> cb.like(root.get("title"), "%" + fragment + "%") }
}
