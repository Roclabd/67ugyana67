package ru.cashbox.portal.transfers

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

data class TransferQuery(val description: String, val minAmount: Long? = null)

@RestController
@RequestMapping("/api/transfers")
class TransferController(private val service: TransferService) {
    @PostMapping("/search")
    fun search(@RequestBody query: TransferQuery) = service.search(query)

    @GetMapping("/large")
    fun large(@RequestParam min: Long) = service.large(min)
}
