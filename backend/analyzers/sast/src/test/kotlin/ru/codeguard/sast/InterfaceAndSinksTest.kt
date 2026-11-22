package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastResult
import ru.codeguard.sast.project.ParseError
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Сервисный слой через интерфейс/абстрактный класс и дополнительные SQL-стоки (Hibernate, jOOQ, Exposed, MyBatis). */
class InterfaceAndSinksTest {

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

    private val searchController = "TicketController.kt" to """
        @RestController
        class TicketController(private val search: TicketSearch) {
            @GetMapping("/api/search")
            fun find(@RequestParam q: String): List<Map<String, Any?>> = search.find(q)
        }
    """

    @Test
    fun `SQL-инъекция через интерфейс и его реализацию`() {
        val r = analyze(
            "TicketSearch.kt" to """
                interface TicketSearch { fun find(q: String): List<Map<String, Any?>> }
                class JdbcTicketSearch(private val jdbc: JdbcTemplate) : TicketSearch {
                    override fun find(q: String) = jdbc.queryForList("SELECT * FROM ticket WHERE note = '${'$'}q'")
                }
            """,
            searchController,
        )
        assertEquals(listOf("sql-injection@TicketSearch.kt:3"), r.classes())
    }

    @Test
    fun `SQL-инъекция через абстрактный класс`() {
        val r = analyze(
            "TicketSearch.kt" to """
                abstract class TicketSearch { abstract fun find(q: String): List<Map<String, Any?>> }
                class JdbcTicketSearch(private val jdbc: JdbcTemplate) : TicketSearch() {
                    override fun find(q: String) = jdbc.queryForList("SELECT * FROM ticket WHERE note = '" + q + "'")
                }
            """,
            searchController,
        )
        assertEquals(listOf("sql-injection@TicketSearch.kt:3"), r.classes())
    }

    @Test
    fun `SQL-инъекция в одной из нескольких реализаций`() {
        val r = analyze(
            "TicketSearch.kt" to """
                interface TicketSearch { fun find(q: String): List<Map<String, Any?>> }
                class SafeSearch(private val jdbc: JdbcTemplate) : TicketSearch {
                    override fun find(q: String) = jdbc.queryForList("SELECT * FROM ticket WHERE note = ?", q)
                }
                class RawSearch(private val jdbc: JdbcTemplate) : TicketSearch {
                    override fun find(q: String) = jdbc.queryForList("SELECT * FROM ticket WHERE note = '${'$'}q'")
                }
            """,
            searchController,
        )
        assertEquals(listOf("sql-injection@TicketSearch.kt:6"), r.classes())
    }

    @Test
    fun `параметризованная реализация интерфейса не находка`() {
        val r = analyze(
            "TicketSearch.kt" to """
                interface TicketSearch { fun find(q: String): List<Map<String, Any?>> }
                class JdbcTicketSearch(private val jdbc: JdbcTemplate) : TicketSearch {
                    override fun find(q: String) = jdbc.queryForList("SELECT * FROM ticket WHERE note = ?", q)
                }
            """,
            searchController,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `IDOR через сервис-интерфейс`() {
        val r = analyze(
            tickets,
            "TicketService.kt" to """
                interface TicketService { fun load(id: Long): Map<String, Any?> }
                class JdbcTicketService(private val jdbc: JdbcTemplate) : TicketService {
                    override fun load(id: Long): Map<String, Any?> =
                        jdbc.queryForMap("SELECT note, customer_id FROM ticket WHERE ticket_id = ?", id)
                }
            """,
            "TicketController.kt" to """
                @RestController
                @RequestMapping("/api/tickets")
                class TicketController(private val service: TicketService) {
                    @GetMapping("/{ticketId}")
                    fun get(@PathVariable ticketId: Long): Map<String, Any?> = service.load(ticketId)
                }
            """,
        )
        assertEquals(listOf("object-authorization@TicketService.kt:3"), r.classes())
    }

    @Test
    fun `IDOR не находка через интерфейс при фильтре по владельцу`() {
        val r = analyze(
            tickets,
            "TicketService.kt" to """
                interface TicketService { fun load(id: Long, owner: String): Map<String, Any?> }
                class JdbcTicketService(private val jdbc: JdbcTemplate) : TicketService {
                    override fun load(id: Long, owner: String): Map<String, Any?> =
                        jdbc.queryForMap("SELECT note FROM ticket WHERE ticket_id = ? AND customer_id = ?", id, owner)
                }
            """,
            "TicketController.kt" to """
                @RestController
                @RequestMapping("/api/tickets")
                class TicketController(private val service: TicketService) {
                    @GetMapping("/{ticketId}")
                    fun get(@PathVariable ticketId: Long, principal: Principal): Map<String, Any?> = service.load(ticketId, principal.name)
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `Hibernate createSQLQuery`() {
        val r = analyze(
            "C.kt" to """
                @RestController
                class C(private val session: Session) {
                    @GetMapping("/a")
                    fun a(@RequestParam n: String) = session.createSQLQuery("SELECT * FROM ticket WHERE note = '${'$'}n'").list()
                }
            """,
        )
        assertEquals(listOf("sql-injection@C.kt:4"), r.classes())
    }

    @Test
    fun `jOOQ fetch resultQuery execute`() {
        for (m in listOf("fetch", "resultQuery", "execute")) {
            val r = analyze(
                "C.kt" to """
                    @RestController
                    class C(private val dsl: DSLContext) {
                        @GetMapping("/a")
                        fun a(@RequestParam n: String) = dsl.$m("SELECT * FROM ticket WHERE note = '${'$'}n'")
                    }
                """,
            )
            assertEquals(listOf("sql-injection@C.kt:4"), r.classes(), m)
        }
    }

    @Test
    fun `jOOQ fetch с биндингом не находка`() {
        val r = analyze(
            "C.kt" to """
                @RestController
                class C(private val dsl: DSLContext) {
                    @GetMapping("/a")
                    fun a(@RequestParam n: String) = dsl.fetch("SELECT * FROM ticket WHERE note = ?", n)
                }
            """,
        )
        assertEquals(emptyList(), r.classes())
    }

    @Test
    fun `Exposed exec`() {
        val r = analyze(
            "C.kt" to """
                @RestController
                class C {
                    @GetMapping("/a")
                    fun a(@RequestParam n: String) = transaction {
                        TransactionManager.current().exec("SELECT * FROM ticket WHERE note = '${'$'}n'")
                    }
                }
            """,
        )
        assertEquals(listOf("sql-injection@C.kt:4"), r.classes())
    }

    @Test
    fun `taint через let`() {
        val r = analyze(
            "C.kt" to """
                @RestController
                class C(private val jdbc: JdbcTemplate) {
                    @GetMapping("/a")
                    fun a(@RequestParam n: String) = jdbc.queryForList(n.let { "SELECT * FROM ticket WHERE note = '${'$'}it'" })
                }
            """,
        )
        assertEquals(listOf("sql-injection@C.kt:4"), r.classes())
    }

    private fun mapper(annotation: String) = arrayOf(
        "TicketMapper.kt" to """
            @Mapper
            interface TicketMapper {
                $annotation
                fun find(@Param("n") name: String): List<Map<String, Any?>>
            }
        """,
        "C.kt" to """
            @RestController
            class C(private val mapper: TicketMapper) {
                @GetMapping("/a")
                fun a(@RequestParam n: String) = mapper.find(n)
            }
        """,
    )

    @Test
    fun `MyBatis подстановка dollar в Select Update Delete`() {
        for (a in listOf(
            "@Select(\"SELECT * FROM ticket WHERE note = '\\\${n}'\")",
            "@Update(\"UPDATE ticket SET note = '\\\${n}'\")",
            "@Delete(\"DELETE FROM ticket WHERE note = '\\\${n}'\")",
        )) {
            val r = analyze(*mapper(a))
            assertEquals(listOf("sql-injection@TicketMapper.kt:3"), r.classes(), a)
        }
    }

    @Test
    fun `MyBatis решётка параметр не находка`() {
        val r = analyze(*mapper("@Select(\"SELECT * FROM ticket WHERE note = #{n}\")"))
        assertEquals(emptyList(), r.classes())
    }
}
