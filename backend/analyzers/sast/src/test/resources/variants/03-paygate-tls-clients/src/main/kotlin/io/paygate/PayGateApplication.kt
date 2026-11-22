package io.paygate

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class PayGateApplication

fun main(args: Array<String>) {
    runApplication<PayGateApplication>(*args)
}
