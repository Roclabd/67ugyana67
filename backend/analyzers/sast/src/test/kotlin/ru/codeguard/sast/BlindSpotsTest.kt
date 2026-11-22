package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastResult
import ru.codeguard.sast.project.ParseError
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Формы уязвимостей и безопасного кода, не покрытые учебным проектом, — по одному тесту на форму.
 * Каждый тест — небольшой проект из строк: Kotlin-файлы и при необходимости schema.sql.
 */
class BlindSpotsTest {

    private fun analyze(vararg files: Pair<String, String>): SastResult {
        val kotlin = mutableListOf<ru.codeguard.sast.project.KotlinSource>()
        val texts = mutableMapOf<String, SourceText>()
        val errors = mutableListOf<ParseError>()
        for ((path, text) in files) {
            if (path.endsWith(".kt")) {
                val (src, errs) = SastProjectLoader.parseKotlin(path, text.trimIndent())
                kotlin += src; errors += errs
            } else texts[path] = SourceText(path, text.trimIndent())
        }
        assertTrue(errors.isEmpty(), "Ошибки разбора тестового кода: $errors")
        return SastAnalyzer().analyze(SastProject(kotlin, texts, errors))
    }

    private fun SastResult.classes() = findings.map { "${it.sastClass}@${it.path}:${it.line}" }

    private val tickets = "schema.sql" to """
        CREATE TABLE ticket (
            ticket_id BIGINT PRIMARY KEY,
            customer_id VARCHAR(48) NOT NULL,
            note VARCHAR(200) NOT NULL
        );
    """

    @Test
    fun `затенение через AntPathRequestMatcher`() {
        val r = analyze(
            "Sec.kt" to """
                class Sec {
                    fun chain(http: HttpSecurity) = http.authorizeHttpRequests { a ->
                        a.requestMatchers(AntPathRequestMatcher("/api/admin/export", "GET")).permitAll()
                        a.requestMatchers(AntPathRequestMatcher("/api/admin/**")).hasRole("ADMIN")
                        a.anyRequest().authenticated()
                    }.build()
                }
            """,
        )
        assertEquals(listOf("route-authorization@Sec.kt:3"), r.classes())
    }

    @Test
    fun `preflight OPTIONS и health не находка, открытый actuator — находка`() {
        val r = analyze(
            "Sec.kt" to """
                class Sec {
                    fun chain(http: HttpSecurity) = http.authorizeHttpRequests { a ->
                        a.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        a.requestMatchers("/actuator/health").permitAll()
                        a.requestMatchers("/actuator/**").permitAll()
                        a.requestMatchers("/api/**").authenticated()
                        a.anyRequest().denyAll()
                    }.build()
                }
            """,
        )
        assertEquals(listOf("route-authorization@Sec.kt:5"), r.classes())
    }

    @Test
    fun `CORS цепочка через переменную`() {
        val r = analyze(
            "Web.kt" to """
                class Web : WebMvcConfigurer {
                    override fun addCorsMappings(registry: CorsRegistry) {
                        val reg = registry.addMapping("/api/**")
                        reg.allowedOriginPatterns("*")
                        reg.allowCredentials(true)
                    }
                }
            """,
        )
        assertEquals(listOf("credentialed-cors@Web.kt:4"), r.classes())
        assertEquals(5, r.findings.single().endLine)
    }

    @Test
    fun `CORS applyPermitDefaultValues с credentials`() {
        val r = analyze(
            "Cors.kt" to """
                class Cors {
                    fun source(): CorsConfiguration {
                        val c = CorsConfiguration().applyPermitDefaultValues()
                        c.allowCredentials = true
                        return c
                    }
                }
            """,
        )
        assertEquals(1, r.findings.count { it.sastClass == "credentialed-cors" }, r.classes().toString())
    }

    @Test
    fun `SQL-инъекция из сообщения Kafka`() {
        val r = analyze(
            "Listener.kt" to """
                class Listener(private val jdbc: JdbcTemplate) {
                    @KafkaListener(topics = ["orders"])
                    fun onOrder(@Payload status: String) {
                        jdbc.update("UPDATE orders SET status = '" + status + "'")
                    }
                }
            """,
        )
        assertEquals(listOf("sql-injection@Listener.kt:3"), r.classes())
    }

    @Test
    fun `TrustManager с checkServerTrusted из одного return`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls {
                    val trustAll = object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { return }
                        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                    }
                }
            """,
        )
        assertEquals(listOf("tls-verification@Tls.kt:2"), r.classes())
    }

    @Test
    fun `проверяющий TrustManager не находка`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls(private val delegate: X509TrustManager) {
                    val pinned = object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                            delegate.checkServerTrusted(chain, authType)
                        }
                        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
                    }
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `IDOR через JdbcClient param`() {
        val r = analyze(
            tickets,
            "TicketController.kt" to """
                @RestController
                @RequestMapping("/api/tickets")
                class TicketController(private val client: JdbcClient) {
                    @GetMapping("/{ticketId}")
                    fun get(@PathVariable ticketId: Long): Map<String, Any?> =
                        client.sql("SELECT ticket_id, customer_id, note FROM ticket WHERE ticket_id = :id")
                            .param("id", ticketId)
                            .query().singleRow()
                }
            """,
        )
        assertEquals(listOf("object-authorization@TicketController.kt:5"), r.classes())
    }

    @Test
    fun `IDOR через Spring Data findById по сущности с владельцем`() {
        val r = analyze(
            "Order.kt" to """
                @Entity
                @Table(name = "orders")
                class Order(@Id val id: Long, @Column(name = "customer_id") val customerId: String, val total: Long)
                interface OrderRepository : JpaRepository<Order, Long>
            """,
            "OrderController.kt" to """
                @RestController
                @RequestMapping("/api/orders")
                class OrderController(private val orders: OrderRepository) {
                    @GetMapping("/{orderId}")
                    fun get(@PathVariable orderId: Long): Order = orders.findById(orderId).orElseThrow()
                }
            """,
        )
        assertTrue(r.classes().any { it.startsWith("object-authorization@") }, r.classes().toString())
    }

    @Test
    fun `TLS — глобальный HostnameVerifier, принимающий любое имя`() {
        val r = analyze(
            "Boot.kt" to """
                object Boot {
                    fun relax() {
                        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
                    }
                }
            """,
        )
        assertTrue(r.classes().any { it.startsWith("tls-verification@Boot.kt") }, r.classes().toString())
    }

    @Test
    fun `SQL-инъекция из поля DTO в @RequestBody`() {
        val r = analyze(
            "SearchController.kt" to """
                data class SearchRequest(val plate: String, val limit: Int)
                @RestController
                class SearchController(private val jdbc: JdbcTemplate) {
                    @PostMapping("/api/search")
                    fun search(@RequestBody req: SearchRequest): List<Map<String, Any>> =
                        jdbc.queryForList("SELECT * FROM vehicle WHERE plate = '" + req.plate + "'")
                }
            """,
        )
        assertEquals(listOf("sql-injection@SearchController.kt:5"), r.classes())
    }

    @Test
    fun `SQL-инъекция из заголовка запроса`() {
        val r = analyze(
            "AuditController.kt" to """
                @RestController
                class AuditController(private val jdbc: JdbcTemplate) {
                    @GetMapping("/api/audit")
                    fun audit(@RequestHeader("X-Tenant") tenant: String): List<Map<String, Any>> =
                        jdbc.queryForList("SELECT * FROM audit WHERE tenant = '${'$'}tenant'")
                }
            """,
        )
        assertEquals(listOf("sql-injection@AuditController.kt:4"), r.classes())
    }

    private fun staffOnlyTickets(role: String) = analyze(
        tickets,
        "Sec.kt" to """
            class Sec {
                fun chain(http: HttpSecurity) = http.authorizeHttpRequests { a ->
                    a.requestMatchers("/api/tickets/**").hasRole("$role")
                    a.anyRequest().authenticated()
                }.build()
            }
        """,
        "TicketController.kt" to """
            @RestController
            @RequestMapping("/api/tickets")
            class TicketController(private val jdbc: JdbcTemplate) {
                @GetMapping("/{ticketId}")
                fun get(@PathVariable ticketId: Long): Map<String, Any?> =
                    jdbc.queryForMap("SELECT note FROM ticket WHERE ticket_id = ?", ticketId)
            }
        """,
    )

    @Test
    fun `IDOR не находка для маршрута только сотрудников с другими названиями ролей`() {
        for (role in listOf("TECHNICIAN", "ENGINEER", "CLERK", "DISPATCHER", "WAREHOUSE_WORKER", "MASTER")) {
            assertEquals(emptyList(), staffOnlyTickets(role).classes(), role)
        }
    }

    @Test
    fun `IDOR находка, если маршрут открыт клиентской роли`() {
        assertEquals(listOf("object-authorization@TicketController.kt:5"), staffOnlyTickets("CUSTOMER").classes())
    }

    @Test
    fun `IDOR не находка при фильтре по владельцу из Principal`() {
        val r = analyze(
            tickets,
            "TicketController.kt" to """
                @RestController
                @RequestMapping("/api/tickets")
                class TicketController(private val jdbc: JdbcTemplate) {
                    @GetMapping("/{ticketId}")
                    fun get(@PathVariable ticketId: Long, principal: Principal): Map<String, Any?> =
                        jdbc.queryForMap("SELECT note FROM ticket WHERE ticket_id = ? AND customer_id = ?", ticketId, principal.name)
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }
}
