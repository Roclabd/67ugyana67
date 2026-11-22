package workflow.analyzers.sast

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeStatus
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Генератор тестов-доказательств на учебном проекте и поведение ноды без песочницы. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProofNodeTest {
    private val repoRoot: Path = Paths.get(requireNotNull(System.getProperty("codeguard.repoRoot")) { "не задан codeguard.repoRoot" })
    private val projectDir: Path = repoRoot.resolve("fixtures/training/sample-project")
    private val json = ObjectMapper()
    private lateinit var builder: ProjectModelBuilder
    private lateinit var model: ProjectModel
    private lateinit var findings: List<JsonNode>

    @BeforeAll
    fun prepare() {
        builder = ProjectModelBuilder()
        model = requireNotNull(builder.build(projectDir).model)
        val out = runBlocking { SastNode().run(Ctx(null), NodeInput(mapOf("model" to model))) }
        findings = (out.ports["findings"] as JsonNode).toList()
    }

    @AfterAll
    fun close() = builder.close()

    @Test
    fun `на учебном проекте три теста - открытый маршрут, IDOR по чужой заявке, SQL-инъекция`() {
        val (cases, unsupported) = ProofPlanner.plan(findings, model)
        val byClass = cases.associateBy { it.sastClass }
        assertEquals(setOf("route-authorization", "object-authorization", "sql-injection"), byClass.keys)
        assertTrue("get(\"/api/pickup/export\")" in byClass.getValue("route-authorization").source)
        val idor = byClass.getValue("object-authorization").source
        assertTrue("get(\"/api/customer/tickets/202\")" in idor && "user(\"rider-copper\")" in idor && "rider-indigo" in idor, idor)
        val sqli = byClass.getValue("sql-injection").source
        assertTrue("get(\"/api/customer/search/frame\")" in sqli && "param(\"frameTag\"" in sqli && "OR '1'='1" in sqli, sqli)
        assertTrue(cases.all { "@SpringBootTest(classes = [lab.servicedesk.ServiceDeskApplication::class])" in it.source })
        assertEquals(setOf("credentialed-cors", "tls-verification"), unsupported.map { it["class"] }.toSet())
    }

    @Test
    fun `без Docker нода не исполняет код на хосте - статус PARTIAL с причиной`(@TempDir work: Path) {
        val noDocker = object : DockerSandbox("codeguard-sandbox") {
            override fun run(project: Path, cases: List<ProofCase>, work: Path, timeoutSeconds: Long) =
                Outcome(emptyMap(), "Песочница недоступна: Docker не запущен")
        }
        val ctx = Ctx(work)
        val out = runBlocking { ProofNode(noDocker).run(ctx, NodeInput(mapOf("workspace" to projectDir, "model" to model, "findings" to findings))) }
        assertEquals(NodeStatus.PARTIAL, out.status)
        val proofs = json.valueToTree<JsonNode>(out.ports["proofs"])
        assertEquals("Песочница недоступна: Docker не запущен", proofs.path("error").asText())
        assertTrue(proofs.path("results").none { it.path("status").asText() == "REPRODUCED" })
        assertEquals(64, proofs.path("projectHash").asText().length)
    }

    private class Ctx(override val workspace: Path?) : NodeContext {
        override val runId = "test"
        override val nodeId = "proof"
        override val params: JsonNode = ObjectMapper().readTree("{}")
        override val trigger: JsonNode = ObjectMapper().createObjectNode()
        override val coverageStatus = "COMPLETE"
        override fun redact(message: String) = message
        override fun log(message: String) {}
        override fun emitProgress(percent: Int, note: String?) {}
    }
}
