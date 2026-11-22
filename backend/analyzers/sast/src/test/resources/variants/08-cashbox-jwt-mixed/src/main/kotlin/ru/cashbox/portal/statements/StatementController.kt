package ru.cashbox.portal.statements

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/statements")
class StatementController(private val service: StatementService) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long, @RequestHeader("Authorization") token: String): Map<String, Any?> =
        service.getForToken(id, token)
}
