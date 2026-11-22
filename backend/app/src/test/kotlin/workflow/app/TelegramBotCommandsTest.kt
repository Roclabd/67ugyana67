package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.CompletableDeferred
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.Primary
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.bean.override.mockito.MockitoBean
import workflow.engine.RunStatus
import workflow.nodes.DeliveryHttpFailure
import workflow.nodes.TelegramAttachment
import workflow.nodes.TelegramDestination
import workflow.nodes.TelegramTransport
import java.nio.file.Files
import java.time.Instant
import java.util.ArrayDeque
import java.util.Collections
import java.util.UUID

private const val BOT_TOKEN = "1234:bot-fixture-token-abcdefgh"
private const val REPO = "https://github.com/acme/app"

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:telegrambot;DB_CLOSE_DELAY=-1",
    "APP_SECRETS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "TELEGRAM_BOT_TOKEN=$BOT_TOKEN",
    "TELEGRAM_CHAT_ID=101",
])
@Import(TelegramBotCommandsTest.FakeConfig::class)
class TelegramBotCommandsTest @Autowired constructor(
    private val settings: TelegramSettingsStore,
    private val transport: FakeBotTransport,
    private val history: RunStore,
    private val workflows: WorkflowStore,
    private val templates: TemplateLibrary,
    private val repositories: RepositorySettingsStore,
    private val reports: ReportService,
    private val json: ObjectMapper,
    private val db: JdbcTemplate,
    private val springBot: TelegramBotCommands,
) {
    @MockitoBean private lateinit var runs: RunService

    class FakeBotTransport : TelegramTransport {
        val messages = Collections.synchronizedList(mutableListOf<JsonNode>())
        val documents = Collections.synchronizedList(mutableListOf<Pair<String, TelegramAttachment>>())
        val script = ArrayDeque<() -> String>()
        val offsets = Collections.synchronizedList(mutableListOf<Long>())
        private val mapper = ObjectMapper()

        override fun message(token: String, body: String) { messages.add(mapper.readTree(body)) }
        override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) {
            documents.add(destination.chatId to attachment)
        }

        override fun updates(token: String, offset: Long, timeoutSeconds: Int): String {
            offsets.add(offset)
            check(timeoutSeconds == 25)
            return synchronized(script) { script.pollFirst() }?.invoke() ?: """{"ok":true,"result":[]}"""
        }
    }

    @TestConfiguration
    class FakeConfig {
        @Bean @Primary fun fakeBotTransport() = FakeBotTransport()
    }

    @BeforeEach
    fun reset() {
        db.update("DELETE FROM run_events")
        db.update("DELETE FROM workflow_runs")
        transport.messages.clear()
        transport.documents.clear()
        transport.script.clear()
        transport.offsets.clear()
        Mockito.reset(runs)
        repositories.replace(json.createObjectNode().apply { putArray("repositories").add(REPO) })
    }

    private fun bot(enabled: Boolean = true, data: java.nio.file.Path = Files.createTempDirectory("bot-data")) =
        TelegramBotCommands(settings, transport, runs, history, workflows, templates, repositories, reports, json,
            enabled, "https://scan.example.com", data.toString()).apply { sleeper = {} }

    private fun script(vararg updates: Triple<Long, Long, String>) {
        val result = updates.joinToString(",") { (id, chat, text) ->
            """{"update_id":$id,"message":{"message_id":$id,"chat":{"id":$chat,"type":"private"},"from":{"id":$chat,"is_bot":false},"text":${json.writeValueAsString(text)}}}"""
        }
        transport.script.add { """{"ok":true,"result":[$result]}""" }
    }

    private fun message(chat: Long, text: String) = Triple(System.nanoTime() % 1_000_000, chat, text)

    private fun finishedRun(rules: Set<String> = setOf("rules-9.9"), name: String = "Демо-проверка"): RunRecord {
        val id = UUID.randomUUID().toString()
        val record = RunRecord(id, UUID.randomUUID().toString(), 1, json.createObjectNode().put("kind", "manual"),
            RunStatus.SUCCESS, Instant.now(), finishedAt = Instant.now(), coverageStatus = "COMPLETE",
            counts = mapOf("CRITICAL" to 1, "HIGH" to 0, "MEDIUM" to 0, "LOW" to 0), rulesVersions = rules,
            workflowName = name,
            report = json.valueToTree(mapOf("runId" to id, "coverage" to mapOf("status" to "COMPLETE"), "findings" to listOf(
                mapOf("id" to "f1", "category" to "SECRET", "class" to "password", "severity" to "CRITICAL",
                    "title" to "Пароль в коде", "path" to "Config.kt", "line" to 1, "secretMasked" to "Zx****")))))
        history.begin(record)
        history.finish(record)
        return record
    }

    /** Mockito возвращает null для матчера, а параметр Kotlin не допускает null: подсовываем пустой объект. */
    private fun anyNode(): JsonNode = ArgumentMatchers.any(JsonNode::class.java) ?: json.createObjectNode()

    private fun texts() = transport.messages.map { it.path("text").asText() }

    private fun await(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertTrue(condition(), "условие не выполнилось за 10 с")
    }

    @Test
    fun `unauthorized chat is ignored silently`() {
        script(message(999, "/status"), message(999, "/help"))
        bot().pollOnce()
        assertTrue(transport.messages.isEmpty())
        assertTrue(transport.documents.isEmpty())
    }

    @Test
    fun `help lists commands and accepts bot suffix`() {
        script(message(101, "/help@CodeguardBot"))
        bot().pollOnce()
        val text = texts().single()
        assertTrue(listOf("/status", "/last", "/run", "/help").all { it in text })
        assertEquals("101", transport.messages.single().path("chat_id").asText())
    }

    @Test
    fun `status shows rules version workflows repositories and last run`() {
        finishedRun()
        workflows.create(workflow.engine.Workflow(name = "один", nodes = listOf(workflow.engine.WorkflowNode("s", "trigger.manual"))))
        script(message(101, "/status"))
        bot().pollOnce()
        val text = texts().single()
        assertTrue("rules-9.9" in text, text)
        assertTrue("Демо-проверка" in text, text)
        assertTrue("крит. 1" in text, text)
        assertTrue("Подключённых репозиториев: 1" in text, text)
        assertTrue("Время сервера" in text, text)
        assertFalse(BOT_TOKEN in text)
    }

    @Test
    fun `last sends the card with buttons and a pdf document`() {
        val run = finishedRun()
        script(message(101, "/last"))
        bot().pollOnce()
        val card = transport.messages.single()
        assertTrue("Пароль в коде" in card.path("text").asText())
        val button = card.path("reply_markup").path("inline_keyboard").path(0).path(1).path("url").asText()
        assertEquals("https://scan.example.com/api/runs/${run.id}/report.pdf", button)
        val (chat, document) = transport.documents.single()
        assertEquals("101", chat)
        assertTrue(document.filename.endsWith(".pdf"))
        assertEquals("%PDF", String(document.content, 0, 4, Charsets.ISO_8859_1))
    }

    @Test
    fun `run of a repository that is not connected is refused`() {
        script(message(101, "/run https://github.com/other/secret-repo"))
        bot().pollOnce()
        assertTrue("не подключён" in texts().single())
        Mockito.verifyNoInteractions(runs)
        assertFalse("https://github.com/other/secret-repo" in repositories.urls())
    }

    private fun stubStart(completion: CompletableDeferred<RunRecord>, id: String = UUID.randomUUID().toString()) {
        Mockito.doReturn(RunTicket(id, completion)).`when`(runs)
            .start(ArgumentMatchers.anyString(), anyNode(), ArgumentMatchers.isNull<String>())
    }

    @Test
    fun `run of a connected repository starts and sends the final card with a pdf`() {
        val record = finishedRun()
        stubStart(CompletableDeferred(record), record.id)
        script(message(101, "/run $REPO/tree/main"))
        val bot = bot()
        bot.pollOnce()
        await { transport.documents.size == 1 && bot.busyChats == 0 }
        val texts = texts()
        assertEquals("Запущено: <code>${record.id}</code>", texts.first())
        assertTrue("Пароль в коде" in texts.last())
        val trigger = ArgumentCaptor.forClass(JsonNode::class.java)
        Mockito.verify(runs).start(ArgumentMatchers.anyString(), (trigger.capture() ?: json.createObjectNode()), ArgumentMatchers.isNull<String>())
        assertEquals(REPO, trigger.value.path("source").path("url").asText())
        val serviceWorkflow = workflows.list().single { it.name == BOT_WORKFLOW_NAME }
        assertTrue(workflows.get(serviceWorkflow.id).nodes.none { it.type.startsWith("notify.") })
    }

    @Test
    fun `second concurrent run in the same chat is refused`() {
        stubStart(CompletableDeferred())
        script(message(101, "/run $REPO"), message(101, "/run $REPO"))
        val bot = bot()
        bot.pollOnce()
        val texts = texts()
        assertTrue(texts[0].startsWith("Запущено"))
        assertTrue("уже идёт" in texts[1], texts[1])
        Mockito.verify(runs, Mockito.times(1))
            .start(ArgumentMatchers.anyString(), anyNode(), ArgumentMatchers.isNull<String>())
    }

    @Test
    fun `more than five runs per hour are refused`() {
        val bot = bot()
        var now = Instant.parse("2026-01-01T00:00:00Z")
        bot.clock = { now }
        repeat(5) { index ->
            val record = finishedRun()
            stubStart(CompletableDeferred(record), record.id)
            script(message(101, "/run $REPO"))
            bot.pollOnce()
            await { transport.documents.size == index + 1 && bot.busyChats == 0 }
        }
        script(message(101, "/run $REPO"))
        bot.pollOnce()
        assertTrue("Лимит" in texts().last(), texts().last())
        now = now.plusSeconds(3601)
        val record = finishedRun()
        stubStart(CompletableDeferred(record), record.id)
        script(message(101, "/run $REPO"))
        bot.pollOnce()
        await { transport.documents.size == 6 }
    }

    @Test
    fun `no free slots is reported politely`() {
        Mockito.doThrow(Conflict("Все четыре слота выполнения заняты")).`when`(runs)
            .start(ArgumentMatchers.anyString(), anyNode(), ArgumentMatchers.isNull<String>())
        script(message(101, "/run $REPO"))
        val bot = bot()
        bot.pollOnce()
        assertTrue("слоты заняты" in texts().single())
        assertEquals(0, bot.busyChats)
    }

    @Test
    fun `webhook conflict stops polling after network errors back off`() {
        val bot = bot()
        transport.script.add { throw java.io.IOException("network down") }
        transport.script.add { throw DeliveryHttpFailure(409) }
        bot.runPolling()
        assertEquals(2, transport.offsets.size)
        assertTrue(transport.messages.isEmpty())
    }

    @Test
    fun `offset is persisted between restarts`() {
        val data = Files.createTempDirectory("bot-offset")
        val first = bot(data = data)
        script(Triple(10, 101, "/help"))
        first.pollOnce()
        first.pollOnce()
        assertEquals(listOf(0L, 11L), transport.offsets.toList())
        assertEquals("11", Files.readString(data.resolve("telegram-bot-offset")).trim())
        transport.offsets.clear()
        bot(data = data).pollOnce()
        assertEquals(listOf(11L), transport.offsets.toList())
    }

    @Test
    fun `disabled flag means no polling`() {
        assertFalse(springBot.polling)
        val disabled = bot(enabled = false)
        disabled.start()
        assertFalse(disabled.polling)
        assertTrue(transport.offsets.isEmpty())
    }
}
