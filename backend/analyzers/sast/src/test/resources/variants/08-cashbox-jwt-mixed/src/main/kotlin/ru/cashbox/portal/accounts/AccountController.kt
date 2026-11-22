package ru.cashbox.portal.accounts

import java.security.Principal
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/accounts")
class AccountController(private val jdbc: JdbcTemplate) {
    @GetMapping("/export")
    fun export(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT account_id, owner_id, balance FROM account ORDER BY account_id")

    @GetMapping("/mine")
    fun mine(principal: Principal): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT account_id, balance FROM account WHERE owner_id = ?", principal.name)

    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): Map<String, Any?> =
        jdbc.queryForMap("SELECT account_id, owner_id, balance FROM account WHERE account_id = ?", id)
}
