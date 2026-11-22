package ru.parcelway

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class ParcelWayApplication

fun main(args: Array<String>) {
    runApplication<ParcelWayApplication>(*args)
}
