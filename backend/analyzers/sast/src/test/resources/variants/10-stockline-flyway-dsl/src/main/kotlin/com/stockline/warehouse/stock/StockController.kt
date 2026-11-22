package com.stockline.warehouse.stock

import java.security.Principal
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/stock")
class StockController(private val queries: StockQueries) {
    @GetMapping("/summary")
    fun summary() = queries.summary()

    @GetMapping("/search")
    fun search(@RequestParam name: String) = queries.byName(name)

    @GetMapping("/sku/{sku}")
    fun bySku(@PathVariable sku: String) = queries.bySku(sku)

    @GetMapping("/location")
    fun byLocation(@RequestParam code: String) = queries.byLocation(code)

    @GetMapping("/safe")
    fun safe(@RequestParam name: String, @RequestParam sku: String) =
        queries.byNameSafe(name) + queries.bySkuSafe(sku)
}

@RestController
@RequestMapping("/api/reservations")
class ReservationController(private val repository: ReservationRepository) {
    @GetMapping("/mine")
    fun mine(principal: Principal): List<Reservation> = repository.findByOwnerId(principal.name)

    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): Reservation? =
        repository.findById(id).orElse(null)

    @GetMapping("/{id}/own")
    fun own(@PathVariable id: Long, authentication: Authentication): Reservation? =
        repository.findById(id).filter { it.ownerId == authentication.name }.orElse(null)
}
