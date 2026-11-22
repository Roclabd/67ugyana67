package ru.cashbox.portal.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class JwtService(@Value("\${cashbox.jwt.secret}") secret: String) {
    private val key = Keys.hmacShaKeyFor(secret.toByteArray())

    fun subject(token: String): String = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token.removePrefix("Bearer "))
        .body
        .subject
}
