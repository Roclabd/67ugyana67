package workflow.analyzers.sast

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import ru.codeguard.sast.GroundTruth
import ru.codeguard.sast.SastAnalyzer
import ru.codeguard.sast.project.SastProjectLoader
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Нода SAST поверх ProjectModel модуля C: результат не должен отличаться от автономного прогона SAST,
 * находки проходят contracts/finding.schema.json, покрытие и версия правил на месте.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SastNodeTest {
    private val repoRoot: Path = Paths.get(requireNotNull(System.getProperty("codeguard.repoRoot")) { "не задан codeguard.repoRoot" })
    private val projectDir: Path = repoRoot.resolve("fixtures/training/sample-project")
    private val json = ObjectMapper()
    private lateinit var builder: ProjectModelBuilder
    private lateinit var model: ProjectModel

    @BeforeAll
    fun buildModel() {
        builder = ProjectModelBuilder()
        model = requireNotNull(builder.build(projectDir).model)
    }

    @AfterAll
    fun close() = builder.close()

    private fun run(params: String = "{}", ports: Map<String, Any?> = mapOf("model" to model)): NodeOutput =
        runBlocking { SastNode().run(Context(json.readTree(params)), NodeInput(ports)) }

    private fun findings(out: NodeOutput) = out.ports["findings"] as JsonNode

    @Test
    fun `на учебном проекте 5 из 5 по эталону, покрытие COMPLETE`() {
        val out = run()
        assertEquals(NodeStatus.SUCCESS, out.status)
        assertEquals(SastAnalyzer.RULES_VERSION, out.rulesVersion)
        assertEquals("COMPLETE", (out.coverage as Map<*, *>)["status"])
        val got = findings(out).map { Triple(it["class"].asText(), it["path"].asText(), it["line"].asInt()) }.toSet()
        val truth = GroundTruth.readOrganizerSast(repoRoot.resolve("fixtures/training/ground-truth/training-findings.json"))
            .first.map { Triple(it.cls, it.path, it.line) }.toSet()
        assertEquals(truth, got)
    }

    @Test
    fun `адаптер ProjectModel даёт тот же результат, что автономный загрузчик SAST`() {
        val standalone = SastAnalyzer().analyze(SastProjectLoader.load(projectDir))
        val viaModel = SastAnalyzer().analyze(SastProjectAdapter.from(model))
        assertEquals(standalone.findings, viaModel.findings)
        assertEquals(standalone.coverage.dismissed, viaModel.coverage.dismissed)
        assertEquals(standalone.coverage.unresolved, viaModel.coverage.unresolved)
    }

    @Test
    fun `каждая находка проходит finding schema, id уникальны, отпечаток стабилен`() {
        val schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
        // Схема отдельного определения: только $defs контракта и ссылка на нужное (корневые required отчёта не нужны).
        val defs = json.readTree(repoRoot.resolve("contracts/finding.schema.json").toFile())["\$defs"]
        fun schemaOf(def: String) = schemaFactory.getSchema(json.createObjectNode().apply {
            put("\$schema", "https://json-schema.org/draft/2020-12/schema")
            set<JsonNode>("\$defs", defs)
            put("\$ref", "#/\$defs/$def")
        })
        val findingSchema = schemaOf("finding")
        val coverageSchema = schemaOf("coverage")
        val first = run()
        for (f in findings(first)) {
            val errors = findingSchema.validate(f)
            assertTrue(errors.isEmpty(), "${f["class"]}: $errors")
        }
        assertTrue(coverageSchema.validate(json.valueToTree(first.coverage)).isEmpty())
        val ids = findings(first).map { it["id"].asText() }
        assertEquals(ids.size, ids.toSet().size)
        assertEquals(findings(first), findings(run()), "детерминизм: тот же вход — тот же вывод")
    }

    @Test
    fun `отпечаток меняется вместе с фрагментом`() {
        val f = SastAnalyzer().analyze(SastProjectAdapter.from(model)).findings.first()
        assertNotEquals(SastFindingsJson.fingerprint(f, "a"), SastFindingsJson.fingerprint(f.copy(fragment = f.fragment + " "), "a"))
        assertNotEquals(SastFindingsJson.fingerprint(f, "a"), SastFindingsJson.fingerprint(f, "b"))
    }

    @Test
    fun `параметры сужают классы и порог критичности`() {
        val onlySql = findings(run("""{"classes":["sql-injection"]}"""))
        assertEquals(listOf("sql-injection"), onlySql.map { it["class"].asText() })
        val high = findings(run("""{"minSeverity":"HIGH"}"""))
        assertTrue(high.all { it["severity"].asText() in setOf("HIGH", "CRITICAL") })
        assertEquals(3, high.size())
    }

    @Test
    fun `без модели на входе — FAILED с причиной, а не пустой список`() {
        val out = run(ports = emptyMap())
        assertEquals(NodeStatus.FAILED, out.status)
        val coverage = out.coverage as Map<*, *>
        assertEquals("FAILED", coverage["status"])
        assertEquals(1, (coverage["unresolved"] as List<*>).size)
    }

    @Test
    fun `файл с синтаксической ошибкой анализируется и даёт PARTIAL`() {
        val dir = Files.createTempDirectory("sast-node")
        try {
            Files.createDirectories(dir.resolve("src"))
            Files.writeString(dir.resolve("src/Broken.kt"), "package x\nclass Broken {\n  fun f( {\n}\n")
            ProjectModelBuilder().use { b ->
                val out = runBlocking { SastNode().run(Context(JsonNodeFactory.instance.objectNode()), NodeInput(mapOf("model" to b.build(dir).model))) }
                assertEquals(NodeStatus.PARTIAL, out.status)
                val skipped = (out.coverage as Map<*, *>)["filesSkipped"] as List<*>
                assertEquals("src/Broken.kt", (skipped.single() as Map<*, *>)["path"])
            }
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    private class Context(override val params: JsonNode) : NodeContext {
        override val runId = "test"
        override val nodeId = "sast"
        override val workspace: Path? = null
        override val trigger: JsonNode = JsonNodeFactory.instance.objectNode()
        override val coverageStatus = "COMPLETE"
        override fun redact(message: String) = message
        override fun log(message: String) {}
        override fun emitProgress(percent: Int, note: String?) {}
    }
}
