package workflow.app

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import workflow.engine.*
import java.util.concurrent.TimeUnit

private const val LEAKED = "424242:AAAA-secret-token-for-delivery-test"

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:delivery;DB_CLOSE_DELAY=-1",
    "CI_TOKEN=test-ci",
    "TELEGRAM_BOT_TOKEN=$LEAKED",
])
@AutoConfigureMockMvc
@Import(DeliveryFixtures::class)
class DeliveryStatusTest @Autowired constructor(
    private val store: WorkflowStore,
    private val runs: RunService,
    private val history: RunStore,
    private val mockMvc: MockMvc,
) {
    private fun graph(scan: String, vararg delivery: String, source: String = "test.source"): Workflow {
        val nodes = mutableListOf(
            WorkflowNode("start", "trigger.manual"), WorkflowNode("source", source),
            WorkflowNode("scan", scan), WorkflowNode("report", "output.report"),
        )
        val edges = mutableListOf(
            WorkflowEdge("e1", Endpoint("start", "trigger"), Endpoint("source", "trigger")),
            WorkflowEdge("e2", Endpoint("source", "workspace"), Endpoint("scan", "workspace")),
            WorkflowEdge("e3", Endpoint("scan", "findings"), Endpoint("report", "findings")),
        )
        delivery.forEachIndexed { index, type ->
            nodes.add(WorkflowNode("notify$index", type))
            edges.add(WorkflowEdge("n$index", Endpoint("report", "report"), Endpoint("notify$index", "report")))
        }
        return store.create(Workflow(name = "Delivery", nodes = nodes, edges = edges))
    }

    private fun run(workflow: Workflow): RunRecord {
        val ticket = runs.start(requireNotNull(workflow.id), JsonNodeFactory.instance.objectNode().put("kind", "manual"))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            val run = history.get(ticket.id)
            if (run.status != RunStatus.RUNNING) return run
            Thread.sleep(25)
        }
        error("Run did not finish")
    }

    @Test fun `full success delivers and keeps the strict result`() {
        val run = run(graph("test.scan", "test.notify-ok"))
        assertEquals(RunStatus.SUCCESS, run.status)
        assertEquals("COMPLETE", run.coverageStatus)
        assertEquals("DELIVERED", run.delivery?.status)
        assertNotNull(run.report)
        assertEquals(1, run.counts["HIGH"])
    }

    @Test fun `successful analysis survives a failed notification and the report stays reachable`() {
        val run = run(graph("test.scan", "test.notify-fail"))
        assertEquals(RunStatus.SUCCESS, run.status)
        assertEquals("COMPLETE", run.coverageStatus)
        assertEquals("COMPLETE", run.report?.path("coverage")?.path("status")?.asText())
        assertEquals(1, run.report?.path("findings")?.size())
        assertEquals(NodeStatus.FAILED, run.nodeRuns.first { it.nodeId == "notify0" }.status)
        assertEquals(NodeStatus.SUCCESS, run.nodeRuns.first { it.nodeId == "report" }.status)
        assertEquals("FAILED", run.delivery?.status)
        val failure = run.delivery!!.failed.single()
        assertEquals("notify0", failure.nodeId)
        assertEquals("test.notify-fail", failure.type)
        assertTrue(failure.error.contains("не настроен"))
        assertFalse(failure.error.contains(LEAKED))
        assertFalse(json(run).contains(LEAKED))
        mockMvc.get("/api/runs/${run.id}").andExpect {
            status { isOk() }
            jsonPath("$.status") { value("SUCCESS") }
            jsonPath("$.delivery.status") { value("FAILED") }
            jsonPath("$.delivery.failed[0].nodeId") { value("notify0") }
            jsonPath("$.report.findings.length()") { value(1) }
        }
        mockMvc.get("/api/runs/${run.id}/report.json").andExpect {
            status { isOk() }
        }
        mockMvc.get("/api/runs/${run.id}/report.md").andExpect {
            status { isOk() }
        }
    }

    @Test fun `card sent but attachment failed is a delivery failure only`() {
        val run = run(graph("test.scan", "test.notify-card-only", "test.notify-ok"))
        assertEquals(RunStatus.SUCCESS, run.status)
        assertEquals("COMPLETE", run.coverageStatus)
        assertEquals("PARTIAL", run.delivery?.status)
        assertEquals(listOf("notify0"), run.delivery!!.failed.map { it.nodeId })
        assertEquals(listOf("notify1"), run.delivery!!.delivered)
        assertTrue(run.delivery!!.failed.single().error.contains("карточка отправлена"))
    }

    @Test fun `broken source still fails the run and coverage`() {
        val run = run(graph("test.scan", "test.notify-ok", source = "test.source-broken"))
        assertEquals(RunStatus.FAILED, run.status)
        assertEquals("FAILED", run.coverageStatus)
        assertNull(run.report)
        assertNotNull(run.error)
        // Уведомление о сбое отправляется и учитывается как доставка.
        assertEquals("DELIVERED", run.delivery?.status)
    }

    @Test fun `partial analysis stays partial and is not blamed on delivery`() {
        val run = run(graph("test.scan-partial", "test.notify-ok"))
        assertEquals(RunStatus.PARTIAL, run.status)
        assertEquals("PARTIAL", run.coverageStatus)
        assertEquals("DELIVERED", run.delivery?.status)
        assertNotNull(run.report)
        val broken = run(graph("test.scan-partial", "test.notify-fail"))
        assertEquals(RunStatus.PARTIAL, broken.status)
        assertEquals("PARTIAL", broken.coverageStatus)
        assertEquals("FAILED", broken.delivery?.status)
    }

    @Test fun `ci gate remains strict for runs with failed delivery`() {
        val run = run(graph("test.scan", "test.notify-fail"))
        // Доставка не влияет на гейт, но неподтверждённый снимок по-прежнему блокирует.
        assertEquals("COMMIT_MISMATCH", CiGate.decide(run, "a".repeat(40), "v1").reason)
        val complete = run.copy(counts = mapOf("CRITICAL" to 1))
        assertEquals("COMMIT_MISMATCH", CiGate.decide(complete, "a".repeat(40), "v1").reason)
        val verified = complete.copy(commitsVerified = true,
            trigger = JsonNodeFactory.instance.objectNode().put("commitSha", "a".repeat(40)),
            report = (run.report as com.fasterxml.jackson.databind.node.ObjectNode).deepCopy()
                .put("inputHash", "a".repeat(40)).put("rulesVersion", "v1").also { r ->
                val c = r.with("coverage"); val t = c.with("analyzerTypes"); val b = c.with("byAnalyzer")
                listOf("secret", "sca", "sast").forEach { t.put(it, "analyzer.$it"); b.putObject(it).put("status", "COMPLETE") } }, rulesVersions = setOf("v1"))
        assertEquals("CRITICAL_FINDINGS", CiGate.decide(verified, "a".repeat(40), "v1").reason)
        assertEquals("INCOMPLETE_ANALYSIS", CiGate.decide(verified.copy(coverageStatus = "PARTIAL"), "a".repeat(40), "v1").reason)
        assertEquals("RUN_FAILED", CiGate.decide(verified.copy(status = RunStatus.FAILED), "a".repeat(40), "v1").reason)
    }

    private fun json(run: RunRecord) = com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
        .writeValueAsString(run)
}

private fun fake(
    name: String,
    category: NodeCategory,
    inputs: List<PortSpec> = emptyList(),
    outputs: List<PortSpec> = emptyList(),
    notify: Boolean = false,
    body: suspend (NodeContext, NodeInput) -> NodeOutput,
): NodeDefinition = object : NodeDefinition {
    override val type = name
    override val title = name
    override val category = category
    override val inputs = inputs
    override val outputs = outputs
    override val paramsSchema = JsonNodeFactory.instance.objectNode()
    override val notifyOnFailure = notify
    override suspend fun run(ctx: NodeContext, input: NodeInput) = body(ctx, input)
}

@TestConfiguration(proxyBeanMethods = false)
class DeliveryFixtures {
    private val trigger = PortSpec("trigger", PortType.ANY, false)
    private val workspace = PortSpec("workspace", PortType.WORKSPACE)
    private val findings = PortSpec("findings", PortType.FINDINGS)
    private val report = PortSpec("report", PortType.REPORT, false)
    private val finding = mapOf("id" to "f1", "fingerprint" to "fp1", "severity" to "HIGH", "category" to "SAST",
        "path" to "src/A.kt", "line" to 3, "title" to "Example")

    @Bean fun source(): NodeDefinition = fake("test.source", NodeCategory.SOURCE, listOf(trigger), listOf(workspace)) { ctx, _ ->
        NodeOutput(mapOf("workspace" to (ctx.workspace ?: java.nio.file.Path.of("."))))
    }

    @Bean fun brokenSource(): NodeDefinition = fake("test.source-broken", NodeCategory.SOURCE, listOf(trigger), listOf(workspace)) { _, _ ->
        throw NodeFailure("Источник недоступен.")
    }

    @Bean fun scan(): NodeDefinition = fake("test.scan", NodeCategory.ANALYZER, listOf(workspace), listOf(findings)) { _, _ ->
        NodeOutput(mapOf("findings" to listOf(finding)), coverage = mapOf("status" to "COMPLETE"), rulesVersion = "v1")
    }

    @Bean fun scanPartial(): NodeDefinition = fake("test.scan-partial", NodeCategory.ANALYZER, listOf(workspace), listOf(findings)) { _, _ ->
        NodeOutput(mapOf("findings" to listOf(finding)), coverage = mapOf("status" to "PARTIAL"), rulesVersion = "v1")
    }

    @Bean fun notifyOk(): NodeDefinition = fake("test.notify-ok", NodeCategory.OUTPUT, listOf(report), notify = true) { _, _ ->
        NodeOutput(emptyMap())
    }

    @Bean fun notifyFail(): NodeDefinition = fake("test.notify-fail", NodeCategory.OUTPUT, listOf(report), notify = true) { _, _ ->
        throw NodeFailure("Канал не настроен, токен $LEAKED отклонён.")
    }

    @Bean fun notifyCardOnly(): NodeDefinition = fake("test.notify-card-only", NodeCategory.OUTPUT, listOf(report), notify = true) { _, _ ->
        throw NodeFailure("Telegram: карточка отправлена, файл отчёта не доставлен.")
    }
}
