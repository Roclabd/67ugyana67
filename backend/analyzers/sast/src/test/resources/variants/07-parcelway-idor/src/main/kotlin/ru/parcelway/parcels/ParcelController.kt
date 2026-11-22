package ru.parcelway.parcels

import java.security.Principal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/parcels")
class ParcelController(private val service: ParcelService) {
    @GetMapping("/mine")
    fun mine(principal: Principal): List<ParcelEntity> = service.listFor(principal.name)

    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): ParcelEntity? = service.load(id)

    @GetMapping("/{id}/checked")
    fun getChecked(@PathVariable id: Long): ParcelEntity = service.loadChecked(id)
}
