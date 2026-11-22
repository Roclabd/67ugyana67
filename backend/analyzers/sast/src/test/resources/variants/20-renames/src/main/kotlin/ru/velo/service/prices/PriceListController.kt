package ru.velo.service.prices

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class PriceListController {
    @GetMapping("/api/prices/services")
    fun priceNames() = listOf("Brake cable adjustment", "Wheel truing", "Gear indexing")
}
