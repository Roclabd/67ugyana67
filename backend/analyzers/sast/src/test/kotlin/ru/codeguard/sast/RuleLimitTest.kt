package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.CoverageStatus
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RuleLimitTest {
    @Test
    fun hugeAccessRuleListIsCappedAndRecorded() {
        val rules = (1..500).joinToString("\n") { i ->
            if (i % 2 == 0) "                authorize(\"/api/p$i/**\", permitAll)" else "                authorize(\"/api/p$i/**\", hasRole(\"ADMIN\"))"
        }
        val text = """
            package demo
            import org.springframework.context.annotation.Bean
            import org.springframework.context.annotation.Configuration
            import org.springframework.security.config.annotation.web.builders.HttpSecurity
            import org.springframework.security.config.annotation.web.invoke
            import org.springframework.security.web.SecurityFilterChain
            @Configuration
            class Sec {
                @Bean
                fun chain(http: HttpSecurity): SecurityFilterChain {
                    http {
                        authorizeHttpRequests {
        $rules
                            authorize(anyRequest, denyAll)
                        }
                    }
                    return http.build()
                }
            }
        """.trimIndent()
        val (src, errs) = SastProjectLoader.parseKotlin("Sec.kt", text)
        val started = System.nanoTime()
        val result = SastAnalyzer().analyze(SastProject(listOf(src), emptyMap(), errs))
        val seconds = (System.nanoTime() - started) / 1e9
        assertTrue(seconds < 3.0, "took $seconds s")
        assertTrue(result.coverage.unresolved.any { it.kind == "rule-limit" && "слишком много правил доступа" in it.reason })
        assertEquals(CoverageStatus.PARTIAL, result.coverage.status)
    }
}
