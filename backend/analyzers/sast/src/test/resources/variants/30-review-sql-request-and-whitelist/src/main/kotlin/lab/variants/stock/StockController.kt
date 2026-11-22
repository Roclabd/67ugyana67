package lab.variants.stock

import jakarta.servlet.http.HttpServletRequest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class StockController(private val jdbc: JdbcTemplate) {
    // A servlet parameter is still attacker-controlled, even without @RequestParam.
    @GetMapping("/api/stock/search")
    fun search(request: HttpServletRequest): List<Map<String, Any>> {
        val sku = request.getParameter("sku") ?: ""
        return jdbc.queryForList(
            "SELECT sku, price FROM stock_item WHERE sku = '$sku'",
        )
    }

    // Both possible identifiers are fixed by the server before SQL execution.
    @GetMapping("/api/stock/sorted")
    fun sorted(@RequestParam sort: String): List<Map<String, Any>> {
        require(sort in setOf("sku", "price"))
        return jdbc.queryForList(
            "SELECT sku, price FROM stock_item ORDER BY $sort",
        )
    }
}
