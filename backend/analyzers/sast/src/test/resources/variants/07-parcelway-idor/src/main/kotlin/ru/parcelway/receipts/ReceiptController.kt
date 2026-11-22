package ru.parcelway.receipts

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/receipts")
class ReceiptController(private val jdbc: JdbcTemplate) {
    @GetMapping("/mine")
    fun mine(@AuthenticationPrincipal user: UserDetails): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT id, amount FROM receipt WHERE user_id = ?", user.username)

    @GetMapping("/{id}")
    fun receipt(@PathVariable id: Long): Map<String, Any?> =
        jdbc.queryForMap("SELECT id, user_id, amount FROM receipt WHERE id = ?", id)

    @GetMapping("/{id}/own")
    fun own(@PathVariable id: Long, @AuthenticationPrincipal user: UserDetails): Map<String, Any?> =
        jdbc.queryForMap("SELECT id, amount FROM receipt WHERE id = ? AND user_id = ?", id, user.username)
}
