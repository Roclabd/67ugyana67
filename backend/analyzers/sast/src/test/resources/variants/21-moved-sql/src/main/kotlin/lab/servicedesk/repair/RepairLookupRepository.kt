package lab.servicedesk.repair

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

@Repository
class RepairLookupRepository(private val jdbc: JdbcTemplate) {
    fun search(tag: String): List<String> {
        val sql = "SELECT ticket_code FROM repair_ticket WHERE frame_tag = '" + tag + "'"
        return jdbc.queryForList(sql, String::class.java)
    }
}
