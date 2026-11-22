package ru.codeguard.ai

import org.junit.jupiter.api.Test
import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.ai.usefulness.Usefulness
import kotlin.test.assertEquals

/** Проверки полезности на исправлениях, которые выдала живая модель на учебном проекте. */
class UsefulnessTest {
    private val readerSource = """
        package lab.servicedesk.repair

        import org.springframework.jdbc.core.JdbcTemplate

        @Repository
        class RepairTicketReader(private val jdbc: JdbcTemplate) {
            fun read(ticketId: Long): RepairTicket? = jdbc.query(
                "SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?",
                { row, _ -> RepairTicket(row.getString(1), row.getString(2), row.getString(3)) },
                ticketId,
            ).firstOrNull()
        }
    """.trimIndent()

    private val tlsSource = """
        internal class SupplierHttpsClient {
            fun newConnection(): HttpsURLConnection {
                val url = URI("https://supplier.example/catalog").toURL()
                return (url.openConnection() as HttpsURLConnection).apply {
                    connectTimeout = 2_000
                    readTimeout = 2_000
                    hostnameVerifier = HostnameVerifier { _, _ -> true }
                }
            }
        }
    """.trimIndent()

    private val files = mapOf("Reader.kt" to readerSource, "Tls.kt" to tlsSource)
    private val usefulness = Usefulness(Advisories.EMPTY) { files[it] }

    @Test
    fun `IDOR - исправление на уровне репозитория с AND customer_id засчитывается`() {
        val f = AiFinding("f-5", "SAST", "object-authorization", "HIGH", "Reader.kt", 7, 8)
        val fix = """
            fun read(ticketId: Long, customerId: String): RepairTicket? = jdbc.query(
                "SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ? AND customer_id = ?",
                { row, _ -> RepairTicket(row.getString(1), row.getString(2), row.getString(3)) },
                ticketId,
                customerId,
            ).firstOrNull()
        """.trimIndent()
        val c = usefulness.checks(f, fix, null)
        assertEquals(true, c["fixParses"])
        assertEquals(true, c["fixPattern"])
        assertEquals(true, c["sameIdentifier"])
    }

    @Test
    fun `IDOR - фильтр только по id без владельца не засчитывается`() {
        val f = AiFinding("f-5", "SAST", "object-authorization", "HIGH", "Reader.kt", 7, 8)
        val fix = """fun read(ticketId: Long) = jdbc.query("SELECT * FROM repair_ticket WHERE ticket_id = ?", mapper, ticketId)"""
        assertEquals(false, usefulness.checks(f, fix, null)["fixPattern"])
    }

    @Test
    fun `TLS - исправление удаляет верификатор, имена сверяются по соседним строкам`() {
        val f = AiFinding("f-3", "SAST", "tls-verification", "MEDIUM", "Tls.kt", 7)
        val fix = """
            return (url.openConnection() as HttpsURLConnection).apply {
                connectTimeout = 2_000
                readTimeout = 2_000
            }
        """.trimIndent()
        val c = usefulness.checks(f, fix, null)
        assertEquals(true, c["sameIdentifier"])
        assertEquals(true, c["fixPattern"])
        assertEquals(true, c["rerunClean"])
    }
}
