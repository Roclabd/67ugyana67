package ru.velo.service.jobs

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/client")
class JobController(private val jobs: JobReader) {
    @GetMapping("/tickets/{id}")
    fun getJob(@PathVariable id: Long): ResponseEntity<Job> =
        ResponseEntity.ofNullable(jobs.fetch(id))

    @GetMapping("/overview")
    fun overview(principal: Principal): Map<String, Any> =
        mapOf("customerId" to principal.name, "openTickets" to jobs.openCount(principal.name))
}
