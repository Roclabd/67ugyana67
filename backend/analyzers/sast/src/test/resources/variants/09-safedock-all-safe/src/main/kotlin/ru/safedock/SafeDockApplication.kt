package ru.safedock

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SafeDockApplication

fun main(args: Array<String>) {
    runApplication<SafeDockApplication>(*args)
}
