package ru.cashbox.portal.security

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

data class LoginRequest(val login: String, val password: String)

@RestController
@RequestMapping("/api/auth")
class AuthController(private val login: LoginService) {
    @PostMapping("/login")
    fun login(@RequestBody request: LoginRequest): Map<String, String> =
        mapOf("token" to login.issueToken(request.login, request.password))
}
