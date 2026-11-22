package ru.cashbox.portal.statements

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import ru.cashbox.portal.security.JwtService

class IsNotOwnerException(message: String) : RuntimeException(message)

@Service
class StatementService(private val jdbc: JdbcTemplate, private val jwt: JwtService) {
    fun getForToken(id: Long, token: String): Map<String, Any?> {
        val statement = jdbc.queryForMap(
            "SELECT statement_id, owner_id, period, total FROM statement WHERE statement_id = ?",
            id,
        )
        if (statement["owner_id"] != jwt.subject(token)) {
            throw IsNotOwnerException("statement $id belongs to another client")
        }
        return statement
    }
}
