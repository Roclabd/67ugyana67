package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.Primary
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.put
import workflow.engine.Redaction
import workflow.engine.RunStatus
import workflow.nodes.DeliveryHttpFailure
import workflow.nodes.TelegramAttachment
import workflow.nodes.TelegramDestination
import workflow.nodes.TelegramTransport
import java.time.Instant
import java.time.OffsetDateTime
import java.util.Collections
import java.util.UUID

private const val ENV_TOKEN = "1234:environment-fixture-token"
private const val STORED_TOKEN = "4321:settings-fixture-token"
private const val URL = "/api/integrations/telegram"

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:telegram;DB_CLOSE_DELAY=-1",
    "APP_SECRETS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "TELEGRAM_BOT_TOKEN=$ENV_TOKEN",
    "TELEGRAM_CHAT_ID=101",
])
@AutoConfigureMockMvc
@Import(TelegramIntegrationTest.FakeTransportConfig::class)
class TelegramIntegrationTest @Autowired constructor(
    private val mvc: MockMvc,
    private val json: ObjectMapper,
    private val db: JdbcTemplate,
    private val transport: FakeTransport,
    private val runs: RunStore,
    private val compare: RunCompareService,
) {
    class FakeTransport : TelegramTransport {
        val sent = Collections.synchronizedList(mutableListOf<Pair<String, String>>())
        var failure: RuntimeException? = null

        override fun message(token: String, body: String) {
            failure?.let { throw it }
            sent += token to body
        }

        override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) = Unit
    }

    @TestConfiguration
    class FakeTransportConfig {
        @Bean @Primary fun fakeTelegramTransport() = FakeTransport()
    }

    @BeforeEach
    fun reset() {
        db.update("DELETE FROM telegram_settings")
        transport.sent.clear()
        transport.failure = null
    }

    @Test
    fun storesEncryptedTokenAndOnlyReturnsItsMask() {
        mvc.get(URL).andExpect {
            status { isOk() }
            jsonPath("$.token") { value(Redaction.MASK) }
            jsonPath("$.tokenSaved") { value(false) }
            jsonPath("$.chatId") { value("101") }
            jsonPath("$.attachments[0]") { value("pdf") }
            jsonPath("$.attachments.length()") { value(1) }
        }

        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"token":"$STORED_TOKEN","chatId":"-202","attachments":["sarif","pdf"]}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.token") { value(Redaction.MASK) }
            jsonPath("$.tokenSaved") { value(true) }
        }
        val stored = db.queryForObject("SELECT payload FROM telegram_settings WHERE id = 1", String::class.java)
        assertNotNull(stored)
        assertFalse(stored!!.contains(STORED_TOKEN))
        assertNotEquals(Redaction.MASK, json.readTree(stored).path("sealedToken").asText())

        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"token":"${Redaction.MASK}","format":"md"}"""
        }.andExpect { status { isOk() } }
        mvc.get(URL).andExpect {
            jsonPath("$.token") { value(Redaction.MASK) }
            jsonPath("$.chatId") { value("-202") }
            jsonPath("$.attachments[0]") { value("md") }
            jsonPath("$.attachments.length()") { value(1) }
        }
        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"attachments":["md","md"]}"""
        }.andExpect { status { isUnprocessableEntity() } }
        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"attachments":[]}"""
        }.andExpect { status { isOk() }; jsonPath("$.attachments.length()") { value(0) } }
        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"attachments":["md","pdf"]}"""
        }.andExpect { status { isOk() } }
        test("{}", 200)
        assertEquals(STORED_TOKEN, transport.sent.single().first)
        assertEquals("-202", json.readTree(transport.sent.single().second).path("chat_id").asText())

        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"token":"","chatId":""}"""
        }.andExpect {
            jsonPath("$.tokenSaved") { value(false) }
            jsonPath("$.chatId") { value("101") }
        }
        test("{}", 200)
        assertEquals(ENV_TOKEN, transport.sent.last().first)
    }

    @Test
    fun testConnectionReturnsSafeErrorsAndCanUseUnsavedInput() {
        test("""{"token":"invalid"}""", 401, "TELEGRAM_TOKEN")
        test("""{"chatId":"https://telegram.example/"}""", 400, "TELEGRAM_CHAT")
        assertTrue(transport.sent.isEmpty())
        mvc.post("$URL/test") {
            contentType = MediaType.TEXT_PLAIN
            content = "{}"
        }.andExpect { status { isUnsupportedMediaType() } }

        val input = """{"token":"$STORED_TOKEN","chatId":"-303","language":"en"}"""
        transport.failure = DeliveryHttpFailure(401)
        test(input, 401, "TELEGRAM_TOKEN")
        transport.failure = DeliveryHttpFailure(400)
        test(input, 400, "TELEGRAM_CHAT")
        transport.failure = DeliveryHttpFailure(403)
        test(input, 403, "TELEGRAM_FORBIDDEN")
        transport.failure = DeliveryHttpFailure(429)
        test(input, 429, "TELEGRAM_RATE_LIMIT")
        transport.failure = IllegalStateException("https://api.telegram.org/bot$STORED_TOKEN")
        test(input, 502, "TELEGRAM_NETWORK")
        transport.failure = null
        test(input, 200)
        assertEquals(STORED_TOKEN, transport.sent.single().first)
        val message = json.readTree(transport.sent.single().second)
        assertEquals("-303", message.path("chat_id").asText())
        assertTrue(message.path("text").asText().contains("connection confirmed"))
        assertFalse(message.toString().contains(STORED_TOKEN))
        assertEquals(0, requireNotNull(db.queryForObject("SELECT COUNT(*) FROM telegram_settings", Int::class.java)))
    }

    @Test
    fun savesAndTestsRecipientListsLongerThanThePreviousLimit() {
        val recipients = (1..32).map { "-100123456%03d".format(it) }
        val chatList = (recipients + recipients.last()).joinToString(", ")
        mvc.put(URL) {
            contentType = MediaType.APPLICATION_JSON
            content = """{"chatId":"$chatList"}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.chatId") { value(chatList) }
        }
        test("{}", 200)
        val sentChats = transport.sent.map { (_, body) -> json.readTree(body).path("chat_id").asText() }
        assertEquals(recipients.sorted(), sentChats.sorted())
    }

    @Test
    fun previousRunIsCompleteFromSameWorkflowAndDiffIgnoresChangedFingerprints() {
        val workflowId = UUID.randomUUID().toString()
        val original = finding("Original.kt", "original-fingerprint")
        val moved = finding("Original.kt", "changed-fingerprint")
        val added = finding("Added.kt", "added")
        val base = run(workflowId, 1, RunStatus.SUCCESS, "COMPLETE", original)
        run(workflowId, 2, RunStatus.SUCCESS, "PARTIAL", moved)
        run(UUID.randomUUID().toString(), 3, RunStatus.SUCCESS, "COMPLETE", moved)
        val head = run(workflowId, 4, RunStatus.RUNNING, "PARTIAL")
        run(workflowId, 5, RunStatus.SUCCESS, "COMPLETE", moved)
        val comparison = requireNotNull(compare.previous(head, listOf(moved, added)))
        assertEquals(base, comparison.runId)
        assertEquals(listOf(added), comparison.added)
    }

    private fun test(body: String, expectedStatus: Int, expectedCode: String? = null) {
        val response = mvc.post("$URL/test") {
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect {
            status { isEqualTo(expectedStatus) }
            if (expectedCode == null) jsonPath("$.status") { value("sent") }
            else jsonPath("$.code") { value(expectedCode) }
        }.andReturn().response.contentAsString
        assertFalse(response.contains(STORED_TOKEN))
        assertFalse(response.contains(ENV_TOKEN))
    }

    private fun finding(path: String, fingerprint: String): JsonNode =
        json.createObjectNode().put("category", "SECRET").put("path", path)
            .put("class", "fixture").put("severity", "HIGH").put("line", 1).put("fingerprint", fingerprint)

    private fun run(workflow: String, second: Long, status: RunStatus, coverage: String, vararg findings: JsonNode): String {
        val id = UUID.randomUUID().toString()
        val time = Instant.parse("2026-11-22T00:00:00Z").plusSeconds(second)
        val report = json.createObjectNode().set<JsonNode>("findings", json.valueToTree(findings))
        runs.begin(RunRecord(id, workflow, 1, json.createObjectNode(), status, time, report = report, coverageStatus = coverage))
        db.update("UPDATE workflow_runs SET started_at = ? WHERE id = ?", OffsetDateTime.parse(time.toString()), id)
        return id
    }
}
