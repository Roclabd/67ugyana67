package ru.shopwindow

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class ShopWindowApplication

fun main(args: Array<String>) {
    runApplication<ShopWindowApplication>(*args)
}
