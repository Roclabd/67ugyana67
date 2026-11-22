package kz.tradehub

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class TradeHubApplication

fun main(args: Array<String>) {
    runApplication<TradeHubApplication>(*args)
}
