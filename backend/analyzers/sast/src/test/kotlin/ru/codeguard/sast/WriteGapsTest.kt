package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastResult
import ru.codeguard.sast.project.ParseError
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** IDOR на запись/удаление, имена owner-колонок, DTO-идентификатор, TLS-стратегии и CORS-отражение Origin. */
class WriteGapsTest {

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

    // ───────────── IDOR на запись ─────────────

    private val orderEntity = "Order.kt" to """
        @Entity
        @Table(name = "orders")
        class Order(@Id val id: Long, @Column(name = "customer_id") val customerId: String, val total: Long)
        interface OrderRepository : JpaRepository<Order, Long>
    """

    private fun orderController(body: String) = "OrderController.kt" to """
        @RestController
        @RequestMapping("/api/orders")
        class OrderController(private val orders: OrderRepository, private val jdbc: JdbcTemplate) {
            $body
        }
    """

    private fun hasIdor(r: SastResult) = r.classes().any { it.startsWith("object-authorization@") }

    @Test
    fun `IDOR deleteById без проверки владельца`() {
        val r = analyze(orderEntity, orderController("""
            @DeleteMapping("/{orderId}")
            fun remove(@PathVariable orderId: Long) { orders.deleteById(orderId) }
        """.trimIndent()))
        assertTrue(hasIdor(r), r.classes().toString())
    }

    @Test
    fun `IDOR delete(findById) без проверки владельца`() {
        val r = analyze(orderEntity, orderController("""
            @DeleteMapping("/{orderId}")
            fun remove(@PathVariable orderId: Long) { orders.delete(orders.findById(orderId).orElseThrow()) }
        """.trimIndent()))
        assertTrue(hasIdor(r), r.classes().toString())
    }

    @Test
    fun `IDOR PUT - загрузка по id и save без проверки владельца`() {
        val r = analyze(orderEntity, orderController("""
            @PutMapping("/{orderId}")
            fun update(@PathVariable orderId: Long, @RequestParam total: Long): Order {
                val o = orders.findById(orderId).orElseThrow()
                return orders.save(Order(o.id, o.customerId, total))
            }
        """.trimIndent()))
        assertTrue(hasIdor(r), r.classes().toString())
    }

    @Test
    fun `IDOR PATCH - save сущности из DTO с id`() {
        val r = analyze(
            orderEntity,
            "Dto.kt" to "data class OrderPatch(val orderId: Long, val total: Long)",
            orderController("""
                @PatchMapping
                fun patch(@RequestBody dto: OrderPatch): Order = orders.save(Order(dto.orderId, "x", dto.total))
            """.trimIndent()),
        )
        assertTrue(hasIdor(r), r.classes().toString())
    }

    @Test
    fun `IDOR SQL UPDATE по id без владельца`() {
        val r = analyze(
            "schema.sql" to "CREATE TABLE ticket (ticket_id BIGINT PRIMARY KEY, customer_id VARCHAR(48), note VARCHAR(200));",
            "TicketController.kt" to """
                @RestController
                class TicketController(private val jdbc: JdbcTemplate) {
                    @PutMapping("/api/tickets/{ticketId}")
                    fun edit(@PathVariable ticketId: Long, @RequestParam note: String) {
                        jdbc.update("UPDATE ticket SET note = ? WHERE ticket_id = ?", note, ticketId)
                    }
                }
            """,
        )
        assertEquals(listOf("object-authorization@TicketController.kt:4"), r.classes())
    }

    @Test
    fun `IDOR SQL DELETE по id без владельца`() {
        val r = analyze(
            "schema.sql" to "CREATE TABLE ticket (ticket_id BIGINT PRIMARY KEY, customer_id VARCHAR(48), note VARCHAR(200));",
            "TicketController.kt" to """
                @RestController
                class TicketController(private val jdbc: JdbcTemplate) {
                    @DeleteMapping("/api/tickets/{ticketId}")
                    fun drop(@PathVariable ticketId: Long) {
                        jdbc.update("DELETE FROM ticket WHERE ticket_id = ?", ticketId)
                    }
                }
            """,
        )
        assertEquals(listOf("object-authorization@TicketController.kt:4"), r.classes())
    }

    @Test
    fun `SQL UPDATE и DELETE с условием по владельцу из Principal - не находка`() {
        val r = analyze(
            "schema.sql" to "CREATE TABLE ticket (ticket_id BIGINT PRIMARY KEY, customer_id VARCHAR(48), note VARCHAR(200));",
            "TicketController.kt" to """
                @RestController
                class TicketController(private val jdbc: JdbcTemplate) {
                    @PutMapping("/api/tickets/{ticketId}")
                    fun edit(@PathVariable ticketId: Long, @RequestParam note: String, principal: Principal) {
                        jdbc.update("UPDATE ticket SET note = ? WHERE ticket_id = ? AND customer_id = ?", note, ticketId, principal.name)
                    }
                    @DeleteMapping("/api/tickets/{ticketId}")
                    fun drop(@PathVariable ticketId: Long, principal: Principal) {
                        jdbc.update("DELETE FROM ticket WHERE ticket_id = ? AND customer_id = ?", ticketId, principal.name)
                    }
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `deleteById с проверкой владельца не находка`() {
        val r = analyze(orderEntity, orderController("""
            @DeleteMapping("/{orderId}")
            fun remove(@PathVariable orderId: Long, auth: Authentication) {
                val o = orders.findById(orderId).orElseThrow()
                if (o.customerId != auth.name) throw AccessDeniedException("no")
                orders.deleteById(orderId)
            }
        """.trimIndent()))
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `POST создание с внешним ключом из DTO не находка`() {
        val r = analyze(
            orderEntity,
            "Dto.kt" to "data class NewOrder(val productId: Long, val total: Long)",
            orderController("""
                @PostMapping
                fun create(@RequestBody dto: NewOrder): Order = orders.save(Order(0, "x", dto.total + dto.productId))
            """.trimIndent()),
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `DELETE по таблице без владельца не находка`() {
        val r = analyze(
            "Cat.kt" to """
                @Entity
                @Table(name = "categories")
                class Category(@Id val id: Long, val title: String)
                interface CategoryRepository : JpaRepository<Category, Long>
            """,
            "CategoryController.kt" to """
                @RestController
                class CategoryController(private val cats: CategoryRepository) {
                    @DeleteMapping("/api/categories/{id}")
                    fun remove(@PathVariable id: Long) { cats.deleteById(id) }
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    // ───────────── Имена owner-колонок и DTO-идентификатор ─────────────

    private fun readByOwnerColumn(column: String) = analyze(
        "schema.sql" to "CREATE TABLE doc (doc_id BIGINT PRIMARY KEY, $column VARCHAR(48), body VARCHAR(200));",
        "DocController.kt" to """
            @RestController
            class DocController(private val jdbc: JdbcTemplate) {
                @GetMapping("/api/docs/{docId}")
                fun get(@PathVariable docId: Long): Map<String, Any?> =
                    jdbc.queryForMap("SELECT body FROM doc WHERE doc_id = ?", docId)
            }
        """,
    )

    @Test
    fun `owner-колонки разных названий`() {
        for (c in listOf("created_by", "author_id", "author", "assignee", "assignee_id", "tenant_id", "tenant", "account_id", "customer_id", "client_id", "user_id", "owner_name", "owner_id", "creator_id")) {
            assertEquals(listOf("object-authorization@DocController.kt:4"), readByOwnerColumn(c).classes(), c)
        }
    }

    @Test
    fun `owner-колонки с суффиксами login username email uid handle ref`() {
        for (c in listOf("member_login", "patient_login", "user_username", "customer_email", "client_uid", "owner_handle", "account_ref", "tenant_ref", "author_login")) {
            assertEquals(listOf("object-authorization@DocController.kt:4"), readByOwnerColumn(c).classes(), c)
        }
    }

    @Test
    fun `не-owner колонки с похожими суффиксами остаются тихими`() {
        for (c in listOf("doctor_name", "doctor_login", "member_name", "title_ref", "order_email", "supplier_handle", "passport_uid")) {
            assertEquals(emptyList(), readByOwnerColumn(c).classes(), c)
        }
    }

    @Test
    fun `выборка с фильтром по member_login не находка`() {
        val r = analyze(
            "schema.sql" to "CREATE TABLE loan (loan_id BIGINT PRIMARY KEY, member_login VARCHAR(48), due VARCHAR(20));",
            "LoanRepository.kt" to """
                @Repository
                class LoanRepository(private val jdbc: JdbcTemplate) {
                    fun loadOwned(loanId: Long, memberLogin: String) =
                        jdbc.query("SELECT * FROM loan WHERE loan_id = ? AND member_login = ?", mapper, loanId, memberLogin)
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `обычные колонки не owner`() {
        for (c in listOf("title", "status", "category_id", "created_at")) {
            assertEquals(emptyList(), readByOwnerColumn(c).classes(), c)
        }
    }

    @Test
    fun `IDOR - идентификатор из поля тела запроса`() {
        val r = analyze(
            orderEntity,
            "Dto.kt" to "data class OrderRef(val orderId: Long)",
            orderController("""
                @PostMapping("/lookup")
                fun lookup(@RequestBody dto: OrderRef): Order = orders.findById(dto.orderId).orElseThrow()
            """.trimIndent()),
        )
        assertTrue(hasIdor(r), r.classes().toString())
    }

    @Test
    fun `идентификатор из тела запроса с проверкой владельца не находка`() {
        val r = analyze(
            orderEntity,
            "Dto.kt" to "data class OrderRef(val orderId: Long)",
            orderController("""
                @PostMapping("/lookup")
                fun lookup(@RequestBody dto: OrderRef, principal: Principal): Order {
                    val o = orders.findById(dto.orderId).orElseThrow()
                    check(o.customerId == principal.name)
                    return o
                }
            """.trimIndent()),
        )
        assertEquals(emptyList(), r.classes())
    }

    // ───────────── TLS ─────────────

    @Test
    fun `TLS - TrustStrategy всегда true`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls {
                    fun ctx() = SSLContextBuilder().loadTrustMaterial(null, TrustStrategy { _, _ -> true }).build()
                }
            """,
        )
        assertEquals(listOf("tls-verification@Tls.kt:2"), r.classes())
    }

    @Test
    fun `TLS - loadTrustMaterial с trailing lambda`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls {
                    fun ctx() = SSLContextBuilder().loadTrustMaterial(null) { chain, authType -> true }.build()
                }
            """,
        )
        assertEquals(listOf("tls-verification@Tls.kt:2"), r.classes())
    }

    @Test
    fun `TLS - object TrustStrategy с isTrusted true`() {
        val r = analyze(
            "Tls.kt" to """
                class AnyCert : TrustStrategy {
                    override fun isTrusted(chain: Array<X509Certificate>, authType: String): Boolean = true
                }
            """,
        )
        assertEquals(listOf("tls-verification@Tls.kt:1"), r.classes())
    }

    @Test
    fun `TLS - TrustStrategy с реальной проверкой не находка`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls(private val pinned: Set<String>) {
                    fun ctx() = SSLContextBuilder().loadTrustMaterial(null) { chain, _ -> chain.any { it.subjectX500Principal.name in pinned } }.build()
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `TLS - checkServerTrusted проглатывает исключение`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls(private val delegate: X509TrustManager) {
                    val lax = object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                            try {
                                delegate.checkServerTrusted(chain, authType)
                            } catch (e: Exception) {
                                // ignore
                            }
                        }
                        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                    }
                }
            """,
        )
        assertEquals(listOf("tls-verification@Tls.kt:2"), r.classes())
    }

    @Test
    fun `TLS - checkServerTrusted пробрасывает исключение не находка`() {
        val r = analyze(
            "Tls.kt" to """
                class Tls(private val delegate: X509TrustManager) {
                    val strict = object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                            try {
                                delegate.checkServerTrusted(chain, authType)
                            } catch (e: Exception) {
                                throw CertificateException("untrusted", e)
                            }
                        }
                        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
                    }
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    // ───────────── CORS ─────────────

    private fun corsHandler(body: String) = analyze(
        "Cors.kt" to """
            @RestController
            class CorsController {
                @GetMapping("/api/me")
                fun me(request: HttpServletRequest, response: HttpServletResponse): String {
                    $body
                    return "ok"
                }
            }
        """,
    )

    @Test
    fun `CORS - Origin через константу HttpHeaders ORIGIN`() {
        val r = corsHandler("""
            response.setHeader("Access-Control-Allow-Origin", request.getHeader(HttpHeaders.ORIGIN))
            response.setHeader("Access-Control-Allow-Credentials", "true")
        """.trimIndent())
        assertEquals(listOf("credentialed-cors@Cors.kt:5"), r.classes())
    }

    @Test
    fun `CORS - Origin в переменной и константы заголовков`() {
        val r = corsHandler("""
            val origin = request.getHeader("Origin")
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin)
            response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
        """.trimIndent())
        assertEquals(listOf("credentialed-cors@Cors.kt:6"), r.classes())
    }

    @Test
    fun `CORS - Origin из переменной после проверки по списку не находка`() {
        val r = corsHandler("""
            val origin = request.getHeader(HttpHeaders.ORIGIN)
            if (origin in setOf("https://app.example.com")) {
                response.setHeader("Access-Control-Allow-Origin", origin)
                response.setHeader("Access-Control-Allow-Credentials", "true")
            }
        """.trimIndent())
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `CORS - фиксированный origin с credentials не находка`() {
        val r = corsHandler("""
            response.setHeader("Access-Control-Allow-Origin", "https://app.example.com")
            response.setHeader("Access-Control-Allow-Credentials", "true")
        """.trimIndent())
        assertEquals(emptyList(), r.classes())
    }

    private fun patterns(pattern: String) = analyze(
        "Web.kt" to """
            class Web : WebMvcConfigurer {
                override fun addCorsMappings(registry: CorsRegistry) {
                    registry.addMapping("/**").allowedOriginPatterns("$pattern").allowCredentials(true)
                }
            }
        """,
    )

    @Test
    fun `CORS - allowedOriginPatterns https-звезда с credentials`() {
        assertEquals(listOf("credentialed-cors@Web.kt:3"), patterns("https://*").classes())
        assertEquals(listOf("credentialed-cors@Web.kt:3"), patterns("*").classes())
    }

    @Test
    fun `CORS - шаблон поддоменов с credentials - находка, порт localhost и точный origin - нет`() {
        assertEquals(listOf("credentialed-cors@Web.kt:3"), patterns("https://*.example.com").classes())
        assertEquals(listOf("credentialed-cors@Web.kt:3"), patterns("*.example.com").classes())
        assertEquals(emptyList(), patterns("http://localhost:*").classes())
        assertEquals(emptyList(), patterns("https://portal.example.com").classes())
    }

    @Test
    fun `CORS - CorsConfiguration setAllowedOriginPatterns https-звезда`() {
        val r = analyze(
            "Web.kt" to """
                class Web {
                    fun source(): CorsConfigurationSource {
                        val c = CorsConfiguration()
                        c.setAllowedOriginPatterns(listOf("https://*"))
                        c.allowCredentials = true
                        return UrlBasedCorsConfigurationSource().also { it.registerCorsConfiguration("/**", c) }
                    }
                }
            """,
        )
        assertEquals(listOf("credentialed-cors@Web.kt:4"), r.classes())
    }
}
