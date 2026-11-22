package kz.tradehub.web

import java.security.Principal
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/catalog")
class CatalogController(private val jdbc: JdbcTemplate) {
    @GetMapping("/items")
    fun items(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT sku, title, price FROM product WHERE published = TRUE ORDER BY title")
}

@RestController
@RequestMapping("/api/admin")
class AdminExportController(private val jdbc: JdbcTemplate) {
    @GetMapping("/export")
    fun export(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT sku, title, price, stock FROM product ORDER BY sku")

    @GetMapping("/margins")
    fun margins(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT sku, price - cost AS margin FROM product ORDER BY sku")
}

@RestController
@RequestMapping("/api/account")
class AccountController {
    @GetMapping("/profile")
    fun profile(principal: Principal): Map<String, String> = mapOf("login" to principal.name)
}

@RestController
@RequestMapping("/internal/ops")
class OpsController {
    @PostMapping("/flush-cache")
    fun flushCache(): Map<String, Boolean> = mapOf("flushed" to true)
}
