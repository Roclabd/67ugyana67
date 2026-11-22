package ru.fleetdesk

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class FleetDeskApplication

fun main(args: Array<String>) {
    runApplication<FleetDeskApplication>(*args)
}
