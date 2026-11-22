package ru.parcelway.orders

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/orders")
class OrderController(private val reader: OrderReader) {
    @GetMapping("/{id}")
    fun getOrder(@PathVariable id: Long): ResponseEntity<OrderView> =
        ResponseEntity.ofNullable(reader.read(id))

    @GetMapping("/{id}/own")
    fun getOwnOrder(@PathVariable id: Long, principal: Principal): ResponseEntity<OrderView> =
        ResponseEntity.ofNullable(reader.readOwned(id, principal.name))

    @GetMapping("/mine")
    fun mine(principal: Principal): List<OrderView> = reader.listFor(principal.name)
}
