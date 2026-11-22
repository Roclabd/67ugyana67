package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Аудит: route-authorization (A1), IDOR с Principal (A2), TLS (A3), CORS (A4), глубина taint (A5). Положительные и отрицательные формы. */
class AuditOpusTest {
    private fun analyze(vararg files: Pair<String, String>): List<SastFinding> {
        val kotlin = mutableListOf<ru.codeguard.sast.project.KotlinSource>()
        val texts = mutableMapOf<String, SourceText>()
        for ((path, text) in files) {
            if (path.endsWith(".kt")) {
                val (src, errs) = SastProjectLoader.parseKotlin(path, text.trimIndent())
                assertTrue(errs.isEmpty(), "$errs")
                kotlin += src
            } else texts[path] = SourceText(path, text.trimIndent())
        }
        return SastAnalyzer().analyze(SastProject(kotlin, texts, emptyList())).findings
    }

    private fun List<SastFinding>.of(cls: String) = filter { it.sastClass == cls }.map { "${it.path}:${it.line}" }

    private fun sec(vararg rules: String, header: String = "") = "Sec.kt" to """
        $header
        class Sec {
            fun chain(http: HttpSecurity) = http.authorizeHttpRequests { a ->
                ${rules.joinToString("\n                ")}
            }.build()
        }
    """

    // ── A1(a) admin + authenticated ──
    @Test fun `admin только authenticated - находка`() {
        val f = analyze(sec("a.requestMatchers(\"/api/admin/**\").authenticated()", "a.anyRequest().denyAll()"))
        assertEquals(listOf("Sec.kt:4"), f.of("route-authorization"))
    }

    @Test fun `admin с hasRole и обычный authenticated - не находка`() {
        val f = analyze(sec("a.requestMatchers(\"/api/admin/**\").hasRole(\"ADMIN\")", "a.requestMatchers(\"/api/profile/**\").authenticated()", "a.anyRequest().denyAll()"))
        assertEquals(emptyList(), f.of("route-authorization"))
    }

    // ── A1(b) permitAll на чувствительных данных без затенения ──
    @Test fun `permitAll на export и users - находка`() {
        val f = analyze(sec("a.requestMatchers(\"/api/export/**\").permitAll()", "a.requestMatchers(\"/api/users/**\").permitAll()", "a.anyRequest().authenticated()"))
        assertEquals(listOf("Sec.kt:4", "Sec.kt:5"), f.of("route-authorization"))
    }

    @Test fun `permitAll на health, public, login, docs - не находка`() {
        val f = analyze(sec(
            "a.requestMatchers(\"/actuator/health\", \"/api/public/**\", \"/login\", \"/api/auth/register\").permitAll()",
            "a.requestMatchers(\"/swagger-ui/**\", \"/v3/api-docs/**\", \"/static/**\").permitAll()",
            "a.anyRequest().authenticated()",
        ))
        assertEquals(emptyList(), f.of("route-authorization"))
    }

    // ── A1(c) метод без @PreAuthorize среди методов с ролями ──
    private val ctrl = { extra: String -> "Ctl.kt" to """
        @EnableMethodSecurity
        class MethodSec

        @RestController
        @RequestMapping("/api/invoices")
        class InvoiceController {
            @PreAuthorize("hasRole('ACCOUNTANT')")
            @GetMapping("/{id}") fun get(@PathVariable id: Long): String = "x"
            @PreAuthorize("hasRole('ACCOUNTANT')")
            @PostMapping fun create(@RequestBody b: String): String = "x"
            $extra
        }
    """ }

    @Test fun `один метод без проверки среди методов с ролями - находка`() {
        val f = analyze(ctrl("@DeleteMapping(\"/{id}\") fun remove(@PathVariable id: Long) {}"))
        assertEquals(listOf("Ctl.kt:11"), f.of("route-authorization"))
    }

    @Test fun `все методы с ролями - не находка`() {
        val f = analyze(ctrl("@PreAuthorize(\"hasRole('ADMIN')\") @DeleteMapping(\"/{id}\") fun remove(@PathVariable id: Long) {}"))
        assertEquals(emptyList(), f.of("route-authorization"))
    }

    // ── A1(d) permitAll на методе ──
    @Test fun `PreAuthorize permitAll на отчётах - находка`() {
        val f = analyze("Ctl.kt" to """
            @RestController
            @RequestMapping("/api/reports")
            class ReportController {
                @PreAuthorize("permitAll()")
                @GetMapping("/export") fun export(): String = "csv"
            }
        """)
        assertEquals(listOf("Ctl.kt:5"), f.of("route-authorization"))
    }

    @Test fun `PermitAll на публичном маршруте - не находка`() {
        val f = analyze("Ctl.kt" to """
            @RestController
            @RequestMapping("/api/public")
            class InfoController {
                @PermitAll
                @GetMapping("/info") fun info(): String = "ok"
            }
        """)
        assertEquals(emptyList(), f.of("route-authorization"))
    }

    // ── A1(e) массивы путей ──
    @Test fun `requestMatchers со spread массива констант - находка`() {
        val f = analyze(sec(
            "a.requestMatchers(*OPEN_PATHS).permitAll()", "a.requestMatchers(\"/api/admin/**\").hasRole(\"ADMIN\")", "a.anyRequest().authenticated()",
            header = "private val OPEN_PATHS = arrayOf(\"/api/admin/export\")",
        ))
        assertEquals(listOf("Sec.kt:4"), f.of("route-authorization"))
    }

    @Test fun `requestMatchers со spread публичных путей - не находка`() {
        val f = analyze(sec(
            "a.requestMatchers(*OPEN_PATHS).permitAll()", "a.requestMatchers(\"/api/admin/**\").hasRole(\"ADMIN\")", "a.anyRequest().authenticated()",
            header = "private val OPEN_PATHS = arrayOf(\"/login\", \"/api/public/**\")",
        ))
        assertEquals(emptyList(), f.of("route-authorization"))
    }

    // ── A2 IDOR: Principal ──
    private val parcels = "schema.sql" to """
        CREATE TABLE parcel (parcel_id BIGINT PRIMARY KEY, recipient_email VARCHAR(80) NOT NULL, note VARCHAR(200));
    """

    @Test fun `Principal получен, но не доходит до чтения - находка`() {
        val f = analyze(parcels, "ParcelController.kt" to """
            @RestController
            @RequestMapping("/api/parcels")
            class ParcelController(private val jdbc: JdbcTemplate) {
                @GetMapping("/{parcelId}")
                fun get(@PathVariable parcelId: Long, principal: Principal): Map<String, Any?> {
                    val who = principal.name
                    audit(who, parcelId)
                    return jdbc.queryForMap("SELECT note FROM parcel WHERE parcel_id = ?", parcelId)
                }
                private fun audit(who: String, id: Long) { println(who) }
            }
        """)
        assertEquals(1, f.of("object-authorization").size, f.toString())
    }

    @Test fun `Principal доходит до WHERE - не находка`() {
        val f = analyze(parcels, "ParcelController.kt" to """
            @RestController
            @RequestMapping("/api/parcels")
            class ParcelController(private val jdbc: JdbcTemplate) {
                @GetMapping("/{parcelId}")
                fun get(@PathVariable parcelId: Long, principal: Principal): Map<String, Any?> {
                    val who = principal.name
                    return jdbc.queryForMap("SELECT note FROM parcel WHERE parcel_id = ? AND recipient_email = ?", parcelId, who)
                }
            }
        """)
        assertEquals(emptyList(), f.of("object-authorization"))
    }

    @Test fun `Принципал сравнивается с владельцем загруженной записи - не находка`() {
        val f = analyze(parcels, "ParcelController.kt" to """
            @RestController
            @RequestMapping("/api/parcels")
            class ParcelController(private val jdbc: JdbcTemplate) {
                @GetMapping("/{parcelId}")
                fun get(@PathVariable parcelId: Long, principal: Principal): Map<String, Any?> {
                    val row = jdbc.queryForMap("SELECT note, recipient_email FROM parcel WHERE parcel_id = ?", parcelId)
                    if (!(row["recipient_email"] as String).equals(principal.name)) throw IllegalStateException("no")
                    return row
                }
            }
        """)
        assertEquals(emptyList(), f.of("object-authorization"))
    }

    @Test fun `расширенные owner-колонки - sender_email - находка`() {
        val f = analyze("schema.sql" to "CREATE TABLE msg (msg_id BIGINT PRIMARY KEY, sender_email VARCHAR(80), body VARCHAR(200));",
            "MsgController.kt" to """
            @RestController
            @RequestMapping("/api/msgs")
            class MsgController(private val jdbc: JdbcTemplate) {
                @GetMapping("/{msgId}")
                fun get(@PathVariable msgId: Long): Map<String, Any?> =
                    jdbc.queryForMap("SELECT body FROM msg WHERE msg_id = ?", msgId)
            }
        """)
        assertEquals(1, f.of("object-authorization").size)
    }

    // ── A3 TLS ──
    @Test fun `disableHostnameVerification и пустой endpointIdentificationAlgorithm - находки`() {
        val f = analyze("Net.kt" to """
            class Net {
                fun a() { System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true") }
                fun b(p: SSLParameters) { p.endpointIdentificationAlgorithm = null }
                fun c(p: SSLParameters) { p.setEndpointIdentificationAlgorithm("") }
                fun d() { val v = HostnameVerifier { _, _ -> ALLOW }; client.hostnameVerifier(v) }
                companion object { const val ALLOW = true }
            }
        """)
        assertEquals(listOf("Net.kt:2", "Net.kt:3", "Net.kt:4", "Net.kt:5"), f.of("tls-verification"))
    }

    @Test fun `безопасные настройки TLS - не находка`() {
        val f = analyze("Net.kt" to """
            class Net {
                fun a() { System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "false") }
                fun b(p: SSLParameters) { p.endpointIdentificationAlgorithm = "HTTPS" }
                fun c() { System.setProperty("user.timezone", "UTC") }
            }
        """)
        assertEquals(emptyList(), f.of("tls-verification"))
    }

    // ── A5 глубина taint ──
    private fun deepChain(hops: Int): List<SastFinding> {
        val fns = (1..hops).joinToString("\n") { i ->
            if (i < hops) "fun f$i(q: String): List<Any> = f${i + 1}(q)" else "fun f$i(q: String): List<Any> = jdbc.queryForList(\"SELECT * FROM t WHERE n = '\" + q + \"'\")"
        }
        return analyze("Deep.kt" to """
            @RestController
            class DeepController(private val jdbc: JdbcTemplate) {
                @GetMapping("/api/deep")
                fun find(@RequestParam q: String): List<Any> = f1(q)
                $fns
            }
        """)
    }

    @Test fun `SQLi через 5 вызовов - находка, через 7 - нет`() {
        assertEquals(1, deepChain(5).of("sql-injection").size)
        assertEquals(0, deepChain(7).of("sql-injection").size)
    }

    // ── A4 CORS ──
    @Test fun `origins в локальной val с credentials - находка`() {
        val f = analyze("Web.kt" to """
            class Web {
                fun cors(): CorsConfiguration {
                    val origins = listOf("*")
                    val c = CorsConfiguration()
                    c.allowedOriginPatterns = origins
                    c.allowCredentials = true
                    return c
                }
            }
        """)
        assertEquals(1, f.of("credentialed-cors").size, f.toString())
    }

    @Test fun `origins в локальной val - конкретный домен - не находка`() {
        val f = analyze("Web.kt" to """
            class Web {
                fun cors(): CorsConfiguration {
                    val origins = listOf("https://app.example.com")
                    val c = CorsConfiguration()
                    c.allowedOriginPatterns = origins
                    c.allowCredentials = true
                    return c
                }
            }
        """)
        assertEquals(emptyList(), f.of("credentialed-cors"))
    }
}
