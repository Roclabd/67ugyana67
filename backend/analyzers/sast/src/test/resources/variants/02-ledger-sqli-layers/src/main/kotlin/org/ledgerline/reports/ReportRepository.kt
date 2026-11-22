package org.ledgerline.reports

import jakarta.persistence.EntityManager
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.stereotype.Repository

@Repository
class ReportRepository(
    private val em: EntityManager,
    private val jdbc: JdbcTemplate,
    private val named: NamedParameterJdbcTemplate,
) {
    fun findByStatusNative(status: String): List<*> =
        em.createNativeQuery("SELECT * FROM report WHERE status = '$status'", ReportEntity::class.java).resultList

    fun titleLike(q: String): List<Map<String, Any?>> {
        val sql = buildString {
            append("SELECT report_id, title FROM report WHERE archived = FALSE")
            append(" AND title LIKE '%").append(q).append("%'")
        }
        return jdbc.queryForList(sql)
    }

    fun markArchived(before: String): Int {
        val sql = "UPDATE report SET archived = TRUE WHERE created_on < '$before'"
        return jdbc.update(sql)
    }

    fun reportIdsByState(state: String): List<Long> {
        val sql = "SELECT report_id FROM report WHERE status = '" + state + "' ORDER BY report_id"
        return named.query(sql, MapSqlParameterSource()) { rs, _ -> rs.getLong(1) }
    }

    fun findByStatusSafe(status: String): List<ReportEntity> =
        em.createQuery("SELECT r FROM ReportEntity r WHERE r.status = :status", ReportEntity::class.java)
            .setParameter("status", status)
            .resultList

    fun countByStatusSafe(status: String): Int =
        jdbc.queryForObject("SELECT COUNT(*) FROM report WHERE status = ?", Int::class.javaObjectType, status) ?: 0
}
