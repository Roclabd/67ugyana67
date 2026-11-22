package workflow.ai

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import ru.codeguard.ai.FakeLlmClient
import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.llm.LlmConfig
import ru.codeguard.ai.llm.LlmUnavailableException
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.ValidatedExplanation
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * AI-нода и генератор сценария на SPI движка. Инварианты 5.8: набор находок не меняется, в объяснение идёт только
 * прошедшее валидатор, без модели — явное «объяснения не получены», находки уходят дальше в любом случае.
 */
class AiNodesTest {
    private val json = jacksonObjectMapper()
    private val repoRoot: Path = Paths.get(requireNotNull(System.getProperty("codeguard.repoRoot")))
    private val advisories = Advisories.load(repoRoot.resolve("fixtures/training/vulnerability-database/vulnerabilities.json"))
    private val config = LlmConfig("http://fake", "fake-model", maxAttempts = 2)

    private val findings = json.readTree("""[
      {"id":"sast-1","fingerprint":"a","category":"SAST","class":"sql-injection","path":"src/A.kt","line":13,"endLine":14,
       "severity":"HIGH","rule":"sast.sql","title":"SQL","evidence":[{"path":"src/A.kt","line":13,"note":"@RequestParam"}]},
      {"id":"secret-1","fingerprint":"b","category":"SECRET","class":"password","path":"src/B.kt","line":4,
       "severity":"HIGH","rule":"secret.password","secretMasked":"****","evidence":[{"path":"src/B.kt","line":4}]},
      {"id":"sca-1","fingerprint":"c","category":"SCA","path":"build.gradle.kts","line":31,"severity":"CRITICAL","rule":"sca",
       "group":"org.apache.commons","artifact":"commons-text","version":"1.9","advisoryId":"CVE-2022-42889",
       "evidence":[{"path":"build.gradle.kts","line":31}]}
    ]""") as ArrayNode

    private fun node(client: FakeLlmClient?) = AiExplainNode(client, advisories, cache = null)

    private fun run(client: FakeLlmClient?, value: Any? = findings): NodeOutput =
        runBlocking { node(client).run(Context, NodeInput(mapOf("findings" to value))) }

    private fun out(o: NodeOutput) = o.ports["findings"] as ArrayNode
    private fun explanation(o: NodeOutput) = o.ports["explanation"] as AiExplanation

    /** Находки на выходе — те же объекты, к которым добавлено только поле ai. */
    private fun assertSameFindings(o: NodeOutput) {
        val got = out(o)
        assertEquals(findings.size(), got.size())
        findings.zip(got).forEach { (before, after) ->
            assertEquals(before, after.deepCopy<JsonNode>().also { (it as com.fasterxml.jackson.databind.node.ObjectNode).remove("ai") })
            assertTrue(after.has("ai"))
        }
    }

    @Test
    fun `без LLM — PARTIAL, явное «не получены», находки целиком, версия SCA из справочника`() {
        val o = run(client = null)
        assertEquals(NodeStatus.PARTIAL, o.status)
        assertSameFindings(o)
        assertTrue(out(o).all { it["ai"]["status"].asText() == "NOT_RECEIVED" })
        assertEquals("1.10.0", out(o)[2]["ai"]["recommendedVersion"].asText(), "fixedVersions взяты из справочника по advisoryId")
        val e = explanation(o)
        assertTrue(e is ValidatedExplanation)
        assertTrue("не получены" in e.text)
        assertEquals("NOT_RECEIVED", e.ai.status.name)
    }

    @Test
    fun `медленная модель не держит запуск дольше срока — находки на месте, объяснения не получены`() {
        val slow = FakeLlmClient(config, MutableList(10) { { Thread.sleep(30_000); error("не должно дойти") } })
        val started = System.nanoTime()
        val o = runBlocking { AiExplainNode(slow, advisories, cache = null, budgetSeconds = 1).run(Context, NodeInput(mapOf("findings" to findings))) }
        assertTrue((System.nanoTime() - started) / 1_000_000_000 < 15, "нода должна уложиться в срок + запас")
        assertEquals(NodeStatus.PARTIAL, o.status)
        assertSameFindings(o)
        assertTrue("не ответила за 1 с" in explanation(o).text, explanation(o).text)
    }

    @Test
    fun `модель недоступна — то же самое, а не падение ноды`() {
        val client = FakeLlmClient(config, mutableListOf({ throw LlmUnavailableException("timeout") }))
        val o = run(client)
        assertEquals(NodeStatus.PARTIAL, o.status)
        assertSameFindings(o)
        assertTrue("timeout" in explanation(o).text)
    }

    @Test
    fun `ответ модели проходит валидатор, выдуманный CVE вырезан и не попадает в объяснение`() {
        val explain = json.writeValueAsString(mapOf("explanations" to listOf(
            mapOf("id" to "sast-1", "explanation" to "Параметр запроса попадает в SQL. Похоже на CVE-2099-12345.", "impact" to "Утечка данных.",
                "fixSteps" to listOf("Используйте параметры"), "fixExample" to ""),
            mapOf("id" to "secret-1", "explanation" to "Пароль в коде.", "impact" to "Доступ к системе.", "fixSteps" to listOf("Вынести в окружение"), "fixExample" to ""),
            mapOf("id" to "sca-1", "explanation" to "Уязвимая версия commons-text.", "impact" to "RCE.", "fixSteps" to listOf("Обновить"), "fixExample" to ""),
        )))
        val summary = """{"summary":"Главный риск — SQL-инъекция. См. CVE-2099-12345.","priorities":["sast-1","sca-1","nope"],
            "groups":[{"title":"Данные клиентов","ids":["sast-1","secret-1"],"story":"Инъекция и пароль вместе дают доступ к БД."}]}"""
        val client = FakeLlmClient(config, mutableListOf({ explain }, { summary }))
        val o = run(client)

        assertEquals(NodeStatus.SUCCESS, o.status)
        assertSameFindings(o)
        assertTrue(out(o).all { it["ai"]["status"].asText() == "OK" })
        assertFalse("CVE-2099-12345" in out(o).toString())
        val e = explanation(o)
        assertFalse("CVE-2099-12345" in e.text)
        assertTrue("sql-injection · src/A.kt:13" in e.text, e.text)
        assertTrue("объяснения получены для 3 из 3" in e.text, e.text)
        assertTrue(e.ai.validator.rejectedCves >= 1)
    }

    @Test
    fun `вход от logic merge — список JsonNode, повторяющиеся id не теряют находки`() {
        val list = listOf(findings[0], findings[0].deepCopy(), findings[1])
        val o = run(client = null, value = list)
        assertEquals(3, out(o).size())
        assertEquals(listOf("sast-1", "sast-1", "secret-1"), out(o).map { it["id"].asText() })
    }

    @Test
    fun `генератор разбирает ответ модели в Workflow`() {
        val reply = """{"name":"Секреты в 14:00","nodes":[
            {"id":"cron","type":"trigger.cron","params":{"cron":"0 0 14 * * *"},"position":{"x":0,"y":0}},
            {"id":"secret","type":"analyzer.secret"}],
            "edges":[{"from":{"node":"cron","port":"out"},"to":{"node":"secret","port":"model"}}]}"""
        val wf = runBlocking { LlmWorkflowGenerator(FakeLlmClient(config, mutableListOf({ reply }))).generate("каталог + запрос") }
        assertEquals("Секреты в 14:00", wf.name)
        assertEquals(listOf("trigger.cron", "analyzer.secret"), wf.nodes.map { it.type })
        assertEquals("0 0 14 * * *", wf.nodes[0].params["cron"].asText())
        assertEquals(260.0, wf.nodes[1].position.x, "без позиции — раскладка слева направо")
        assertEquals("cron_out_secret_model", wf.edges.single().id)
    }

    @Test
    fun `связь на несуществующую ноду — повтор с текстом ошибки, затем исправленный граф`() {
        val bad = """{"name":"x","nodes":[{"id":"a","type":"trigger.manual"}],"edges":[{"from":{"node":"a","port":"out"},"to":{"node":"ghost","port":"in"}}]}"""
        val good = """{"name":"x","nodes":[{"id":"a","type":"trigger.manual"}],"edges":[]}"""
        val client = FakeLlmClient(config, mutableListOf({ bad }, { good }))
        val wf = runBlocking { LlmWorkflowGenerator(client).generate("q") }
        assertEquals(1, wf.nodes.size)
        assertEquals(2, client.callCount)
        assertTrue("ghost" in client.received[1].last().content)
    }

    @Test
    fun `модель так и не дала корректный граф — исключение, а не пустой сценарий`() {
        val client = FakeLlmClient(config, mutableListOf({ """{"nodes":[]}""" }, { "не JSON" }))
        assertFailsWith<LlmWorkflowGenerator.GenerationFailed> { runBlocking { LlmWorkflowGenerator(client).generate("q") } }
    }

    private object Context : NodeContext {
        override val runId = "run"
        override val nodeId = "ai"
        override val params: JsonNode = JsonNodeFactory.instance.objectNode()
        override val workspace: Path? = null
        override val trigger: JsonNode = JsonNodeFactory.instance.objectNode()
        override val coverageStatus = "COMPLETE"
        override fun redact(message: String) = message
        override fun log(message: String) {}
        override fun emitProgress(percent: Int, note: String?) {}
    }
}
