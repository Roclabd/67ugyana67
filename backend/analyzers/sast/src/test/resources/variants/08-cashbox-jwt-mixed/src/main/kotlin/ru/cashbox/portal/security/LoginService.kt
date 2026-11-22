package ru.cashbox.portal.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import java.util.Date
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.stereotype.Service

@Service
class LoginService(
    private val authentication: AuthenticationManager,
    @Value("\${cashbox.jwt.secret}") secret: String,
    @Value("\${cashbox.jwt.ttl-minutes}") private val ttlMinutes: Long,
) {
    private val key = Keys.hmacShaKeyFor(secret.toByteArray())

    fun issueToken(login: String, password: String): String {
        authentication.authenticate(UsernamePasswordAuthenticationToken(login, password))
        return Jwts.builder()
            .setSubject(login)
            .setExpiration(Date(System.currentTimeMillis() + ttlMinutes * 60_000))
            .signWith(key)
            .compact()
    }
}
