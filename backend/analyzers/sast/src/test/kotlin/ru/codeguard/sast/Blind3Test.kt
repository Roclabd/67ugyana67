package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Третий слепой корпус: GraphQL-обработчики, расширение с константным SQL, именованный «всё доверяю» верификатор. */
class Blind3Test {
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

    private fun List<SastFinding>.of(cls: String) = filter { it.sastClass == cls }

    private val store = "Store.kt" to """
        data class Shipment(val id: Long, val customerId: String, val status: String)

        @Repository
        class ShipmentStore(private val jdbc: JdbcClient) {
            fun findById(id: Long): Shipment? =
                jdbc.sql("SELECT id, customer_id, status FROM shipment WHERE id = :id")
                    .param("id", id)
                    .query { rs, _ -> Shipment(rs.getLong(1), rs.getString(2), rs.getString(3)) }
                    .optional().orElse(null)

            fun findByCustomer(customerId: String): List<Shipment> =
                jdbc.sql("SELECT id, customer_id, status FROM shipment WHERE customer_id = :c")
                    .param("c", customerId)
                    .query { rs, _ -> Shipment(rs.getLong(1), rs.getString(2), rs.getString(3)) }
                    .list()
        }
    """

    // ───── GraphQL: @Argument — данные клиента ─────

    @Test
    fun graphqlQueryByArgumentWithoutOwnerIsIdor() {
        val r = analyze(store, "Gql.kt" to """
            @Controller
            class ShipmentGraphql(private val store: ShipmentStore) {
                @QueryMapping
                fun shipment(@Argument id: Long): Shipment? {
                    val found = store.findById(id)
                    return found
                }
            }
        """).of("object-authorization")
        assertEquals(1, r.size, r.toString())
        assertEquals("Gql.kt", r.single().path)
        assertEquals(5, r.single().line)
    }

    @Test
    fun graphqlQueryByPrincipalIsSilent() {
        val r = analyze(store, "Gql.kt" to """
            @Controller
            class ShipmentGraphql(private val store: ShipmentStore) {
                @QueryMapping
                fun myShipments(principal: Principal): List<Shipment> = store.findByCustomer(principal.name)

                @QueryMapping
                fun shipment(@Argument id: Long, principal: Principal): Shipment? =
                    store.findById(id)?.takeIf { it.customerId == principal.name }
            }
        """).of("object-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    @Test
    fun graphqlMutationArgumentIntoSqlTextIsInjection() {
        val r = analyze("Gql.kt" to """
            @Controller
            class ItemGraphql(private val jdbc: JdbcTemplate) {
                @QueryMapping
                fun items(@Argument sort: String): List<Map<String, Any>> =
                    jdbc.queryForList("SELECT id, name FROM item ORDER BY " + sort)
            }
        """).of("sql-injection")
        assertEquals(1, r.size, r.toString())
    }

    @Test
    fun methodWithoutGraphqlAnnotationIsNotEndpoint() {
        val r = analyze(store, "Plain.kt" to """
            @Component
            class Helper(private val store: ShipmentStore) {
                fun shipment(@Argument id: Long): Shipment? = store.findById(id)
            }
        """).of("object-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    // ───── SQL: расширение с константным текстом ─────

    private val filter = "Filter.kt" to """
        data class PalletFilter(val zone: String = "", val sku: String = "")
        fun PalletFilter.toWhere(): String = "WHERE zone = '${'$'}zone' AND sku = '${'$'}sku'"
        fun PalletFilter.toNamedWhere(): String = "WHERE zone = :zone AND sku = :sku"
    """

    private val controller = "Ctl.kt" to """
        @RestController
        class PalletController(private val reports: PalletReports) {
            @GetMapping("/pallets")
            fun list(filter: PalletFilter) = reports.search(filter)
            @GetMapping("/pallets/safe")
            fun safe(filter: PalletFilter) = reports.searchSafe(filter)
        }
    """

    @Test
    fun constantExtensionOnTaintedReceiverIsSafeAndInterpolatingOneIsInjection() {
        val r = analyze(filter, controller, "Reports.kt" to """
            @Repository
            class PalletReports(private val jdbc: JdbcTemplate, private val named: NamedParameterJdbcTemplate) {
                fun search(filter: PalletFilter): List<Map<String, Any>> =
                    jdbc.queryForList("SELECT id FROM pallet " + filter.toWhere())

                fun searchSafe(filter: PalletFilter): List<Map<String, Any>> =
                    named.queryForList(
                        "SELECT id FROM pallet " + filter.toNamedWhere(),
                        mapOf("zone" to filter.zone, "sku" to filter.sku),
                    )
            }
        """).of("sql-injection")
        assertEquals(1, r.size, r.toString())
        assertEquals(3, r.single().line)
    }

    @Test
    fun extensionWithSameNameAndInterpolationStaysTainted() {
        val r = analyze(filter, controller, "Reports.kt" to """
            @Repository
            class PalletReports(private val jdbc: JdbcTemplate) {
                fun search(filter: PalletFilter): List<Map<String, Any>> =
                    jdbc.queryForList("SELECT id FROM pallet " + filter.toWhere())
                fun searchSafe(filter: PalletFilter): List<Map<String, Any>> =
                    jdbc.queryForList("SELECT id FROM pallet " + filter.toNamedWhere())
            }
        """).of("sql-injection")
        // constant text of toNamedWhere carries no client data; toWhere interpolates it
        assertEquals(1, r.size, r.toString())
    }

    // ───── TLS: именованная фабрика верификатора ─────

    @Test
    fun namedTrustAllVerifierFactoryIsReportedAtInstallation() {
        val r = analyze("Http.kt" to """
            fun acceptAnyHost(): HostnameVerifier = HostnameVerifier { _, _ -> true }

            @Configuration
            class HttpClients {
                @Bean
                fun minibarHttp(): OkHttpClient = OkHttpClient.Builder()
                    .hostnameVerifier(acceptAnyHost())
                    .build()

                @Bean
                fun pmsHttp(): OkHttpClient = OkHttpClient.Builder()
                    .certificatePinner(CertificatePinner.Builder().add("pms.example.test", "sha256/AAAA").build())
                    .build()
            }
        """).of("tls-verification")
        assertEquals(1, r.size, r.toString())
        assertEquals(7, r.single().line)
        assertTrue(r.single().evidence.any { it.line == 1 }, r.single().evidence.toString())
    }

    @Test
    fun unusedTrustAllFactoryKeepsOwnFinding() {
        val r = analyze("Http.kt" to """
            fun acceptAnyHost(): HostnameVerifier = HostnameVerifier { _, _ -> true }
        """).of("tls-verification")
        assertEquals(1, r.size, r.toString())
        assertEquals(1, r.single().line)
    }

    @Test
    fun strictVerifierFactoryIsSilent() {
        val r = analyze("Http.kt" to """
            fun strictHost(): HostnameVerifier = HostnameVerifier { host, session -> host == "api.example.test" && session.isValid }
            class C { fun client(): OkHttpClient = OkHttpClient.Builder().hostnameVerifier(strictHost()).build() }
        """).of("tls-verification")
        assertTrue(r.isEmpty(), r.toString())
    }
}
