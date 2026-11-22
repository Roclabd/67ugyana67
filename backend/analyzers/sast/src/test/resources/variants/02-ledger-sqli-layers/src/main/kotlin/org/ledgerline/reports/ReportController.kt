package org.ledgerline.reports

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

data class ReportFilter(val status: String, val title: String? = null)

@RestController
@RequestMapping("/api/reports")
class ReportController(private val service: ReportService) {
    @PostMapping("/search")
    fun search(@RequestBody filter: ReportFilter) = service.search(filter)

    @GetMapping("/title")
    fun byTitle(@RequestParam q: String) = service.titleSearch(q)

    @GetMapping("/archive")
    fun archive(@RequestParam before: String) = service.archive(before)

    @GetMapping("/state")
    fun byState(@RequestParam state: String) = service.listByState(state)

    @GetMapping("/safe")
    fun safe(@RequestParam status: String) = service.safeSearch(status)
}
