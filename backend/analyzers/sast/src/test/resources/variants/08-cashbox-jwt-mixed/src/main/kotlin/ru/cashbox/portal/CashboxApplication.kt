package ru.cashbox.portal

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class CashboxApplication

fun main(args: Array<String>) {
    runApplication<CashboxApplication>(*args)
}
