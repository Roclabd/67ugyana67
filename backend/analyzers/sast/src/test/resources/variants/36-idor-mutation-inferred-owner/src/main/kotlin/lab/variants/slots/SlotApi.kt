package lab.variants.slots

import java.security.Principal
import java.util.UUID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@Configuration
class SlotSecurity {
    @Bean
    fun security(http: HttpSecurity): SecurityFilterChain = http
        .formLogin(withDefaults())
        .authorizeHttpRequests { it.anyRequest().authenticated() }
        .build()
}

@RestController
@RequestMapping("/api/slots")
class SlotController(private val service: SlotService) {
    @GetMapping
    fun mine(principal: Principal): List<Map<String, Any>> = service.listFor(principal.name)

    @PostMapping("/{slotId}/cancel")
    fun cancel(@PathVariable slotId: UUID) = service.cancel(slotId)

    @PostMapping("/{slotId}/close")
    fun close(@PathVariable slotId: UUID, principal: Principal) = service.close(slotId, principal.name)
}

@Service
class SlotService(private val database: NamedParameterJdbcTemplate) {
    fun listFor(user: String): List<Map<String, Any>> =
        database.queryForList("SELECT * FROM slot WHERE curator_id = :curator", mapOf("curator" to user))

    fun cancel(slotId: UUID) =
        database.update(
            "UPDATE slot SET status = 'CANCELLED' WHERE slot_id = :slotId AND status = 'ACTIVE'",
            mapOf("slotId" to slotId),
        )

    fun close(slotId: UUID, user: String) =
        database.update(
            "UPDATE slot SET status = 'CLOSED' WHERE slot_id = :slotId AND curator_id = :curator",
            mapOf("slotId" to slotId, "curator" to user),
        )
}
