package ru.velo.service

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class VeloServiceApplication

fun main(args: Array<String>) {
    runApplication<VeloServiceApplication>(*args)
}
