package ru.fleetdesk.search

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/fleet")
class VehicleSearchController(
    private val jdbc: JdbcTemplate,
    private val named: NamedParameterJdbcTemplate,
) {
    @GetMapping("/by-plate")
    fun findByPlate(@RequestParam plate: String): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT vehicle_id, plate, make FROM vehicle WHERE plate = '$plate'")

    @GetMapping("/by-dealer/{dealer}")
    fun findByDealer(@PathVariable dealer: String): List<String> =
        jdbc.query(
            "SELECT plate FROM vehicle WHERE dealer_name = '" + dealer + "' ORDER BY plate",
            { row, _ -> row.getString(1) },
        )

    @GetMapping("/by-region")
    fun findByRegion(@RequestHeader("X-Region") region: String): List<Map<String, Any?>> =
        jdbc.queryForList(String.format("SELECT vehicle_id, plate FROM vehicle WHERE region_code = '%s'", region))

    @GetMapping("/by-vin")
    fun findByVin(@RequestParam vin: String): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT vehicle_id, plate FROM vehicle WHERE vin = ?", vin)

    @GetMapping("/{vehicleId}")
    fun findById(@PathVariable vehicleId: Long): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT vehicle_id, plate, make FROM vehicle WHERE vehicle_id = $vehicleId")

    @GetMapping("/by-make")
    fun findByMake(@RequestParam make: String): List<String> =
        named.query(
            "SELECT plate FROM vehicle WHERE make = :make",
            MapSqlParameterSource("make", make),
        ) { row, _ -> row.getString(1) }
}
