package workflow.engine

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.concurrent.CopyOnWriteArrayList

class DagExecutorTest {
    @TempDir lateinit var workspace: Path
    private val json = ObjectMapper().findAndRegisterModules()

    @Test
    fun `inactive branch is skipped and merge receives only the active input`() {
        val definitions = listOf(
            definition("branch", outputs = listOf("yes", "no")) { _, _ -> NodeOutput(mapOf("yes" to "active")) },
            definition("pass", listOf("in"), listOf("out")) { _, input -> NodeOutput(mapOf("out" to input.ports["in"])) },
            definition("join", listOf("left", "right"), listOf("out"), optional = true) { _, input ->
                NodeOutput(mapOf("out" to input.ports.keys.toList()))
            },
        )
        val graph = Workflow(name = "Branches",
            nodes = listOf(WorkflowNode("if", "branch"), WorkflowNode("left", "pass"),
                WorkflowNode("right", "pass"), WorkflowNode("join", "join")),
            edges = listOf(edge("if", "yes", "left", "in"), edge("if", "no", "right", "in"),
                edge("left", "out", "join", "left"), edge("right", "out", "join", "right")))
        val completed = run(graph, definitions)
        assertEquals(RunStatus.SUCCESS, completed.status)
        assertEquals(listOf("if", "left", "right", "join"), completed.nodeRuns.map { it.nodeId })
        assertEquals(NodeStatus.SKIPPED, completed.nodeRuns[2].status)
        assertEquals(json.readTree("""["left"]"""), completed.nodeRuns.last().output["out"])
    }

    @Test
    fun `configured secrets are absent from logs events and output`() {
        val raw = "test-secret-unique"
        val definition = definition("write", outputs = listOf("out")) { ctx, _ ->
            ctx.log("Received $raw")
            ctx.emitProgress(30, raw)
            NodeOutput(mapOf("out" to mapOf(raw to raw, "token" to raw)))
        }
        val events = CopyOnWriteArrayList<RunEvent>()
        val completed = run(Workflow(name = "Logging", nodes = listOf(WorkflowNode("write", "write"))),
            listOf(definition), listOf(raw), events::add)
        assertFalse(completed.toString().contains(raw))
        assertFalse(events.toString().contains(raw))
        assertTrue(completed.toString().contains(Redaction.MASK))
    }

    @Test
    fun `invalid schema unknown node and incompatible ports are rejected`() {
        val valid = definition("known", outputs = listOf("out"), outputType = PortType.WORKSPACE) { _, _ ->
            NodeOutput(emptyMap())
        }
        val target = definition("target", inputs = listOf("in"), inputType = PortType.FINDINGS) { _, _ ->
            NodeOutput(emptyMap())
        }
        val validator = GraphValidator(NodeRegistry(listOf(valid, target)))
        val graph = Workflow(name = "Invalid",
            nodes = listOf(WorkflowNode("one", "known", params = json.createObjectNode().put("unexpected", true)),
                WorkflowNode("two", "target"), WorkflowNode("three", "missing")),
            edges = listOf(edge("one", "out", "two", "in")))
        assertTrue(validator.validate(graph).map { it.code }.containsAll(listOf("UNKNOWN_NODE", "INVALID_PARAMS", "PORT_TYPE")))
    }

    @Test
    fun `hard failure alerts only the selected branch and skips intermediate work`() {
        val sent = CopyOnWriteArrayList<String>()
        val definitions = listOf(
            definition("logic.if", outputs = listOf("yes", "no")) { _, _ -> NodeOutput(mapOf("yes" to "chosen")) },
            definition("source.fail", listOf("in"), listOf("out")) { _, _ -> throw NodeFailure("Архив не найден") },
            definition("intermediate", listOf("in"), listOf("out")) { _, _ -> error("must be skipped") },
            definition("notify.fixture", inputs = listOf("in"), notifyOnFailure = true) { ctx, _ ->
                sent.add("${ctx.nodeId}:${ctx.coverageStatus}:${ctx.failureReason}")
                NodeOutput(emptyMap())
            },
        )
        val graph = Workflow(name = "Failure routing", nodes = listOf(
            WorkflowNode("branch", "logic.if"), WorkflowNode("source", "source.fail"),
            WorkflowNode("middle", "intermediate"), WorkflowNode("selected", "notify.fixture"),
            WorkflowNode("inactive", "notify.fixture"),
        ), edges = listOf(
            edge("branch", "yes", "source", "in"), edge("source", "out", "middle", "in"),
            edge("middle", "out", "selected", "in"), edge("branch", "no", "inactive", "in"),
        ))
        val registry = NodeRegistry(definitions)
        val executor = DagExecutor(registry, GraphValidator(registry), json)
        val trigger = json.createObjectNode()
        val redaction = Redaction(json, emptyList())
        runBlocking {
            val run = executor.execute(graph, "test", trigger, workspace, redaction) {}
            assertEquals(RunStatus.FAILED, run.status)
            assertTrue(sent.isEmpty())
            val updated = executor.notifyFailure(graph, "test", trigger, workspace, redaction, run.nodeRuns,
                "Архив не найден") {}
            assertEquals(listOf("selected:FAILED:Архив не найден"), sent)
            assertEquals(NodeStatus.SKIPPED, updated.first { it.nodeId == "middle" }.status)
            assertEquals(NodeStatus.SKIPPED, updated.first { it.nodeId == "inactive" }.status)
            assertEquals(NodeStatus.SUCCESS, updated.first { it.nodeId == "selected" }.status)
        }
    }

    @Test
    fun `partial analyzer coverage reaches notification with secrets masked`() {
        val definitions = listOf(
            definition("analyzer.fixture", outputs = listOf("out"), category = NodeCategory.ANALYZER) { _, _ ->
                NodeOutput(mapOf("out" to emptyList<String>()), NodeStatus.PARTIAL,
                    json.readTree("""{"status":"PARTIAL","filesSkipped":[{"path":"Broken.kt","line":7,"reason":"raw-fixture"}]}"""))
            },
            definition("notify.fixture", inputs = listOf("in"), outputs = listOf("out"), notifyOnFailure = true) { ctx, _ ->
                assertEquals("PARTIAL", ctx.coverageStatus)
                NodeOutput(mapOf("out" to ctx.coverageByAnalyzer.getValue("scan").path("filesSkipped").first()))
            },
        )
        val graph = Workflow(name = "Partial notification",
            nodes = listOf(WorkflowNode("scan", "analyzer.fixture"), WorkflowNode("mail", "notify.fixture")),
            edges = listOf(edge("scan", "out", "mail", "in")))
        val completed = run(graph, definitions, secrets = listOf("raw-fixture"))
        val gap = completed.nodeRuns.single { it.nodeId == "mail" }.output["out"] as JsonNode
        assertEquals("Broken.kt", gap.path("path").asText())
        assertEquals(7, gap.path("line").asInt())
        assertEquals(Redaction.MASK, gap.path("reason").asText())
    }

    @Test
    fun `reports all failed roots and publishes each before slower peers finish`() {
        val firstPublished = CompletableDeferred<Unit>()
        val definitions = listOf(
            definition("fast.fail", outputs = listOf("out")) { _, _ -> throw NodeFailure("first") },
            definition("slow.fail", outputs = listOf("out")) { _, _ ->
                withTimeout(2000) { firstPublished.await() }
                throw NodeFailure("second")
            },
            definition("join", listOf("left", "right")) { _, _ -> error("must be skipped") },
            definition("start", outputs = listOf("out")) { _, _ -> NodeOutput(mapOf("out" to 1)) },
            definition("other", inputs = listOf("in")) { _, _ -> error("must be skipped") },
        )
        val graph = Workflow(name = "Parallel failures", nodes = listOf(
            WorkflowNode("a", "fast.fail"), WorkflowNode("b", "slow.fail"),
            WorkflowNode("start", "start"), WorkflowNode("join", "join"), WorkflowNode("other", "other"),
        ), edges = listOf(
            edge("a", "out", "join", "left"), edge("b", "out", "join", "right"), edge("start", "out", "other", "in"),
        ))
        val result = run(graph, definitions) { event ->
            if (event.node?.nodeId == "a" && event.node.status == NodeStatus.FAILED) firstPublished.complete(Unit)
        }
        val nodes = result.nodeRuns.associateBy { it.nodeId }
        assertEquals("second", nodes.getValue("b").error)
        assertEquals(SkipCause(SkipReason.UPSTREAM_FAILURE, listOf("a", "b"), listOf("a_join_left", "b_join_right")),
            nodes.getValue("join").skipCause)
        assertEquals(SkipCause(SkipReason.RUN_STOPPED, listOf("a", "b")), nodes.getValue("other").skipCause)
    }

    @Test
    fun `continue on error preserves the active input and keeps unrelated branch neutral`() {
        val definitions = listOf(
            definition("logic.if", outputs = listOf("yes", "no")) { _, _ -> NodeOutput(mapOf("yes" to "active")) },
            definition("fail", outputs = listOf("out")) { _, _ -> throw NodeFailure("fixture") },
            definition("pass", listOf("in"), listOf("out")) { _, input -> NodeOutput(mapOf("out" to input.ports["in"])) },
            definition("join", listOf("left", "right"), listOf("out"), optional = true) { _, input ->
                NodeOutput(mapOf("out" to input.ports.keys.toList()))
            },
        )
        val graph = Workflow(name = "Continue", nodes = listOf(
            WorkflowNode("if", "logic.if"), WorkflowNode("fail", "fail", continueOnError = true),
            WorkflowNode("off", "pass"), WorkflowNode("blocked", "pass"), WorkflowNode("join", "join"),
        ), edges = listOf(
            edge("if", "no", "off", "in"), edge("fail", "out", "blocked", "in"),
            edge("if", "yes", "join", "left"), edge("fail", "out", "join", "right"),
        ))
        val result = run(graph, definitions)
        val nodes = result.nodeRuns.associateBy { it.nodeId }
        assertEquals(RunStatus.PARTIAL, result.status)
        assertEquals(SkipCause(SkipReason.INACTIVE_BRANCH), nodes.getValue("off").skipCause)
        assertEquals(SkipCause(SkipReason.UPSTREAM_FAILURE, listOf("fail"), listOf("fail_blocked_in")),
            nodes.getValue("blocked").skipCause)
        assertEquals(NodeStatus.SUCCESS, nodes.getValue("join").status)
        assertEquals(json.readTree("""["left"]"""), nodes.getValue("join").output["out"])
    }

    @Test
    fun `validator identifies every edge in a cycle alongside an unconnected port`() {
        val pass = definition("pass", listOf("in"), listOf("out")) { _, _ -> NodeOutput(emptyMap()) }
        val graph = Workflow(name = "Cycle", nodes = listOf(
            WorkflowNode("a", "pass"), WorkflowNode("b", "pass"), WorkflowNode("c", "pass"),
        ), edges = listOf(edge("a", "out", "b", "in"), edge("b", "out", "a", "in")))
        val errors = GraphValidator(NodeRegistry(listOf(pass))).validate(graph)
        assertEquals(setOf("a_b_in", "b_a_in"), errors.filter { it.code == "CYCLE" }.map { it.edgeId }.toSet())
        assertTrue(errors.any { it.code == "REQUIRED_INPUT" && it.nodeId == "c" && it.port == "in" })
    }

    private fun run(graph: Workflow, definitions: List<NodeDefinition>, secrets: List<String> = emptyList(),
        publish: (RunEvent) -> Unit = {}): Execution {
        val registry = NodeRegistry(definitions)
        return runBlocking {
            DagExecutor(registry, GraphValidator(registry), json).execute(graph, "test", json.createObjectNode(),
                workspace, Redaction(json, secrets), publish)
        }
    }

    private fun edge(from: String, source: String, to: String, target: String) =
        WorkflowEdge("${from}_${to}_$target", Endpoint(from, source), Endpoint(to, target))

    private fun definition(
        type: String,
        inputs: List<String> = emptyList(),
        outputs: List<String> = emptyList(),
        optional: Boolean = false,
        outputType: PortType = PortType.ANY,
        inputType: PortType = PortType.ANY,
        notifyOnFailure: Boolean = false,
        category: NodeCategory = NodeCategory.LOGIC,
        body: suspend (NodeContext, NodeInput) -> NodeOutput,
    ): NodeDefinition = object : NodeDefinition {
        override val type = type
        override val title = type
        override val category = category
        override val notifyOnFailure = notifyOnFailure
        override val inputs = inputs.map { PortSpec(it, inputType, !optional) }
        override val outputs = outputs.map { PortSpec(it, outputType) }
        override val paramsSchema: JsonNode = json.readTree("""{"type":"object","additionalProperties":false}""")
        override suspend fun run(ctx: NodeContext, input: NodeInput) = body(ctx, input)
    }
}
