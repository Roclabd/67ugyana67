package ru.shopwindow.web

import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class AnnotatedControllers {
    @CrossOrigin(origins = ["*"], allowCredentials = "true")
    @GetMapping("/api/cart/summary")
    fun cartSummary(): Map<String, Any> = mapOf("items" to 3, "total" to 1490)

    @CrossOrigin(origins = ["https://app.example.ru"], allowCredentials = "true")
    @GetMapping("/api/cart/coupons")
    fun coupons(): List<String> = listOf("SPRING5", "FREESHIP")

    @CrossOrigin(origins = ["*"])
    @GetMapping("/api/banners")
    fun banners(): List<String> = listOf("spring-sale", "new-arrivals")
}
