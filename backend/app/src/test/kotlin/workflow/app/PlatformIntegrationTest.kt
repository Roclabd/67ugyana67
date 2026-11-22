package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.CompletableDeferred
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.hamcrest.Matchers.nullValue
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.support.StaticListableBeanFactory
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import workflow.engine.*
import workflow.nodes.SourceNodes
import java.util.Base64
import java.nio.file.Files
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.put
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:platform;DB_CLOSE_DELAY=-1",
    "CI_TOKEN=test-ci",
    "APP_REVIEW_TOKEN=review-fixture",
])
@AutoConfigureMockMvc
@Import(FailureNotificationFixture::class)
class PlatformIntegrationTest @Autowired constructor(
    private val store: WorkflowStore,
    private val db: JdbcTemplate,
    private val runs: RunService,
    private val library: TemplateLibrary,
    private val json: ObjectMapper,
    private val validator: GraphValidator,
    private val registry: NodeRegistry,
    private val mockMvc: MockMvc,
    private val history: RunStore,
    private val failureFixture: FailureNotificationFixture,
    private val findingHistory: FindingHistory,
    private val executor: DagExecutor,
    private val repositorySource: SourceNodes,
) {
    @Test fun `yaml round trip preserves the graph and strips secret fields`() {
        val original = store.create(Workflow(name = "YAML", nodes = listOf(
            WorkflowNode("start", "trigger.manual"),
            WorkflowNode("send", "notify.telegram", json.createObjectNode().put("token", "fixture-key")),
        )))
        val yaml = mockMvc.get("/api/workflows/${original.id}/export.yaml").andExpect {
            status { isOk() }
        }.andReturn().response.contentAsString
        assertFalse(yaml.contains("fixture-key"))
        assertFalse(yaml.contains("token:"))
        mockMvc.post("/api/workflows/import.yaml") {
            contentType = MediaType.valueOf("text/yaml")
            content = yaml
        }.andExpect {
            status { isCreated() }
            jsonPath("$.version") { value(1) }
            jsonPath("$.nodes[1].type") { value("notify.telegram") }
        }
        mockMvc.post("/api/workflows/import.yaml") {
            contentType = MediaType.valueOf("text/yaml")
            content = "name: first\nname: second\nnodes: []\nedges: []"
        }.andExpect { status { isUnprocessableEntity() } }
        mockMvc.post("/api/workflows/import.yaml") {
            contentType = MediaType.valueOf("text/yaml")
            content = "name: Bad\nnodes: [{id: bad, type: missing.plugin}]\nedges: []"
        }.andExpect {
            status { isUnprocessableEntity() }
            jsonPath("$.details.errors[0].code") { value("UNKNOWN_NODE") }
        }
        // text/plain браузер отправит с чужой страницы без CORS-проверки — такой импорт не принимаем.
        mockMvc.post("/api/workflows/import.yaml") {
            contentType = MediaType.TEXT_PLAIN
            content = yaml
        }.andExpect { status { isUnsupportedMediaType() } }
    }

    @Test fun `baseline and acceptance use complete stored evidence and changed fingerprints return`() {
        val saved = store.create(Workflow(name = "Review fixture", nodes = listOf(
            WorkflowNode("start", "trigger.manual"), WorkflowNode("source", "source.repo"),
            WorkflowNode("parse", "analyzer.parse"), WorkflowNode("secret", "analyzer.secret"),
        ), edges = listOf(
            WorkflowEdge("e1", Endpoint("start", "trigger"), Endpoint("source", "trigger")),
            WorkflowEdge("e2", Endpoint("source", "workspace"), Endpoint("parse", "workspace")),
            WorkflowEdge("e3", Endpoint("parse", "model"), Endpoint("secret", "model")),
        )))
        val workflowId = requireNotNull(saved.id)
        val sha = "a".repeat(40)
        fun finding(value: String) = json.createObjectNode().put("fingerprint", value).put("severity", "HIGH")
        fun stored(fingerprints: List<String>, coverage: String = "COMPLETE"): RunRecord {
            val rows = json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(fingerprints.map(::finding))
            val record = RunRecord(UUID.randomUUID().toString(), workflowId, saved.version, json.createObjectNode(),
                RunStatus.SUCCESS, Instant.now(), coverageStatus = coverage, rulesVersions = setOf("review-v1"),
                nodeRuns = listOf(
                    NodeRun("source", NodeStatus.SUCCESS, output = mapOf("revision" to json.createObjectNode()
                        .put("repoUrl", "https://github.com/example-org/training").put("commitSha", sha))),
                    NodeRun("secret", NodeStatus.SUCCESS, output = mapOf("findings" to rows), rulesVersion = "review-v1",
                        coverage = json.createObjectNode().put("status", coverage)),
                ), report = json.createObjectNode().put("inputHash", sha).put("rulesVersion", "review-v1").apply {
                    putObject("coverage").put("status", coverage)
                    set<com.fasterxml.jackson.databind.JsonNode>("findings", rows)
                })
            history.begin(record)
            return record
        }
        val complete = stored(listOf("keep", "gone"))
        val baseline = "/api/workflows/$workflowId/baseline"
        mockMvc.post(baseline) {
            contentType = MediaType.APPLICATION_JSON
            content = json.writeValueAsString(BaselineUpdate(complete.id))
        }.andExpect { status { isUnauthorized() } }
        mockMvc.post(baseline) {
            header("Authorization", "Bearer review-fixture")
            contentType = MediaType.APPLICATION_JSON
            content = json.writeValueAsString(BaselineUpdate(complete.id))
        }.andExpect { status { isNoContent() } }
        assertThrows(workflow.nodes.InputRejected::class.java) {
            findingHistory.setBaseline(workflowId, stored(emptyList(), "PARTIAL").id)
        }

        val newer = stored(listOf("keep", "accepted", "new"))
        findingHistory.acceptRisk(workflowId, RiskAcceptance(newer.id, "accepted", "Проверено владельцем."))
        val snapshot = requireNotNull(executor.analysisSnapshot(saved, newer.nodeRuns))
        val result = findingHistory.changes(snapshot, listOf(finding("keep"), finding("accepted"), finding("new")))
        val tree = json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(result.ports)
        assertEquals("new", tree.at("/findings/0/fingerprint").asText())
        assertEquals(1, tree.path("findings").size())
        assertEquals("gone", tree.at("/details/removedFingerprints/0").asText())
        val changed = snapshot.copy(fingerprints = setOf("changed"))
        assertEquals(1, json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(
            findingHistory.changes(changed, listOf(finding("changed"))).ports).path("findings").size())
    }

    @Test fun `a missing archive records failure and attempts the notification`() {
        val graph = store.create(failureGraph("manual"))
        val trigger = json.createObjectNode().put("kind", "manual").apply {
            putObject("source").put("kind", "upload").put("uploadId", UUID.randomUUID().toString())
        }
        val ticket = runs.start(requireNotNull(graph.id), trigger)
        val completed = awaitTerminal(ticket.id)
        assertEquals(RunStatus.FAILED, completed.status)
        assertEquals("FAILED", completed.coverageStatus)
        assertTrue(completed.error.orEmpty().contains("ZIP-архив не найден"))
        assertEquals(NodeStatus.FAILED, completed.nodeRuns.first { it.nodeId == "source" }.status)
        assertEquals(NodeStatus.SUCCESS, completed.nodeRuns.first { it.nodeId == "delivery" }.status)
        assertTrue(history.events(completed.id, 0).any { it.name == "log" &&
            it.data.path("message").asText().contains("ZIP-архив не найден") })
    }

    @Test fun `invalid scheduled graph leaves an auditable failed run and attempts the notification`() {
        val workflow = store.create(failureGraph("cron"))
        val workflowId = requireNotNull(workflow.id)
        val invalid = workflow.copy(nodes = workflow.nodes + WorkflowNode("removed-plugin", "missing.plugin"))
        db.update("UPDATE workflows SET payload = ? WHERE id = ?", json.writeValueAsString(invalid), workflowId)
        val trigger = json.createObjectNode().put("kind", "cron").put("scheduledAt", "2026-11-21T11:00:00Z")
        runs.startScheduled(workflow, trigger, "start")

        val attempt = history.list(workflowId).single()
        val completed = awaitTerminal(attempt.id)
        assertEquals(RunStatus.FAILED, completed.status)
        assertEquals("FAILED", completed.coverageStatus)
        assertEquals("Сохранённый граф не прошёл проверку.", completed.error)
        assertEquals("2026-11-21T11:00:00Z", completed.trigger.path("scheduledAt").asText())
        assertEquals(NodeStatus.SUCCESS, completed.nodeRuns.single().status)
    }

    @Test fun `a scheduled occurrence is saved and alerted when all execution slots are busy`() {
        val occupied = store.create(Workflow(name = "Occupied slots", nodes = listOf(
            WorkflowNode("start", "trigger.manual"), WorkflowNode("hold", "test.hold-slot"),
        )))
        val trigger = json.createObjectNode().put("kind", "manual")
        val allocated = mutableListOf<RunTicket>()
        try {
            repeat(4) { allocated.add(runs.start(requireNotNull(occupied.id), trigger)) }
            val scheduled = store.create(failureGraph("cron"))
            runs.startScheduled(scheduled, json.createObjectNode().put("kind", "cron"), "start")
            val attempt = history.list(requireNotNull(scheduled.id)).single()
            val completed = awaitTerminal(attempt.id)
            assertEquals(RunStatus.FAILED, completed.status)
            assertEquals("Все четыре слота выполнения заняты", completed.error)
            assertEquals(NodeStatus.SUCCESS, completed.nodeRuns.single().status)
        } finally {
            failureFixture.releaseSlot.complete(Unit)
            allocated.forEach { awaitTerminal(it.id) }
        }
    }

    @Test fun `untrusted hosts are rejected before the API runs`() {
        mockMvc.get("/api/settings/llm") { header("Host", "localhost:8080") }.andExpect {
            status { isOk() }
            jsonPath("$.apiKey") { doesNotExist() }
        }
        mockMvc.get("/api/settings/llm") {
            header("Host", "other.test:8080")
            header("X-Forwarded-Host", "localhost")
        }.andExpect {
            status { isBadRequest() }
            jsonPath("$.code") { value("HOST_NOT_ALLOWED") }
        }
    }

    private fun failureGraph(kind: String): Workflow {
        val params = json.createObjectNode()
        if (kind == "cron") params.put("cron", "0 0 0 1 1 *")
        return Workflow(name = "Failure fixture", nodes = listOf(
            WorkflowNode("start", "trigger.$kind", params), WorkflowNode("source", "source.archive"),
            WorkflowNode("delivery", "test.failure-notification"),
        ), edges = listOf(
            WorkflowEdge("source-in", Endpoint("start", "trigger"), Endpoint("source", "trigger")),
            WorkflowEdge("notify-in", Endpoint("source", "workspace"), Endpoint("delivery", "in")),
        ))
    }

    private fun awaitTerminal(id: String): RunRecord {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            val run = history.get(id)
            if (run.status != RunStatus.RUNNING) return run
            Thread.sleep(25)
        }
        error("Run did not finish: $id")
    }
    @Test fun `save returns frontend graph errors with node identifiers`() {
        val graph = Workflow(name = "Ошибочный сценарий", nodes = listOf(WorkflowNode("unknown", "missing.type")))
        mockMvc.post("/api/workflows") {
            contentType = MediaType.APPLICATION_JSON
            content = json.writeValueAsString(graph)
        }.andExpect {
            status { isUnprocessableEntity() }
            jsonPath("$.code") { value("INVALID_GRAPH") }
            jsonPath("$.details.errors[0].nodeId") { value("unknown") }
            jsonPath("$.details.errors[0].code") { value("UNKNOWN_NODE") }
        }
    }

    @Test fun `run endpoint and history share the public summary during and after a run`() {
        val workflow = store.create(Workflow(name = "Проверка", nodes = listOf(WorkflowNode("manual", "trigger.manual"))))
        val workflowId = requireNotNull(workflow.id)
        val runId = UUID.randomUUID().toString()
        val running = RunRecord(runId, workflowId, workflow.version, json.createObjectNode().put("kind", "manual"),
            RunStatus.RUNNING, Instant.now(), workflowName = workflow.name)
        history.begin(running)

        mockMvc.get("/api/runs/$runId").andExpect {
            status { isOk() }
            jsonPath("$.runId") { value(runId) }
            jsonPath("$.workflowName") { value(workflow.name) }
            jsonPath("$.workflowVersion") { value(1) }
            jsonPath("$.trigger") { value("manual") }
            jsonPath("$.coverageStatus") {
                hasJsonPath()
                value(nullValue())
            }
            jsonPath("$.finishedAt") {
                hasJsonPath()
                value(nullValue())
            }
            jsonPath("$.report") {
                hasJsonPath()
                value(nullValue())
            }
            jsonPath("$.nodeRuns") { isArray() }
            jsonPath("$.rulesVersions") { doesNotExist() }
        }
        mockMvc.get("/api/runs") { param("workflowId", workflowId) }.andExpect {
            status { isOk() }
            jsonPath("$[0].runId") { value(runId) }
            jsonPath("$[0].coverageStatus") {
                hasJsonPath()
                value(nullValue())
            }
            jsonPath("$[0].counts.CRITICAL") { value(0) }
        }

        history.finish(running.copy(status = RunStatus.PARTIAL, finishedAt = Instant.now(), counts = mapOf("HIGH" to 1)))
        mockMvc.get("/api/runs/$runId").andExpect {
            status { isOk() }
            jsonPath("$.coverageStatus") { value("PARTIAL") }
            jsonPath("$.counts.HIGH") { value(1) }
            jsonPath("$.counts.LOW") { value(0) }
        }
    }

    @Test fun `repository settings apply immediately and invalid updates preserve the previous list`() {
        val endpoint = "/api/settings/repositories"
        val url = "https://gitlab.com/team/demo/project"
        try {
            mockMvc.get(endpoint).andExpect { status { isOk() } }
            mockMvc.put(endpoint) {
                contentType = MediaType.APPLICATION_JSON
                content = """{"repositories":["$url","$url"]}"""
            }.andExpect {
                status { isOk() }
                jsonPath("$.repositories[0]") { value(url) }
                jsonPath("$.repositories[1]") { doesNotExist() }
            }
            repositorySource.validateRepository(url)
            for (invalid in listOf("http://gitlab.com/team/project", "https://github.com/team/..",
                "https://github.com/team/project?key=fixture-marker")) {
                val response = mockMvc.put(endpoint) {
                    contentType = MediaType.APPLICATION_JSON
                    content = """{"repositories":["$invalid"]}"""
                }.andExpect { status { isUnprocessableEntity() } }.andReturn().response
                assertFalse(response.contentAsString.contains("fixture-marker"))
            }
            mockMvc.get(endpoint).andExpect {
                status { isOk() }
                jsonPath("$.repositories[0]") { value(url) }
            }
        } finally {
            db.update("DELETE FROM repository_settings")
        }
    }

    @Test fun `a link typed by the user is connected automatically and never hits the allowlist error`() {
        val endpoint = "/api/settings/repositories"
        val canonical = "https://github.com/fresh-owner/fresh-repo"
        fun repositories() = json.readTree(mockMvc.get(endpoint).andReturn().response.contentAsString).path("repositories")
            .map { it.asText() }
        try {
            // Шаблон с новой ссылкой (с /tree/ и .git) подключает репозиторий, повтор не создаёт дубль.
            repeat(2) {
                mockMvc.post("/api/templates/release/copy") {
                    contentType = MediaType.APPLICATION_JSON
                    content = """{"repoUrl":"$canonical.git/tree/main"}"""
                }.andExpect { status { isCreated() } }
            }
            assertEquals(1, repositories().count { it == canonical })

            // Сценарий с новой ссылкой в source.repo: запуск не падает с ошибкой списка разрешённых.
            val other = "https://github.com/another-owner/another-repo"
            val created = json.readTree(mockMvc.post("/api/workflows") {
                contentType = MediaType.APPLICATION_JSON
                content = json.writeValueAsString(Workflow(name = "Свежая ссылка", nodes = listOf(
                    WorkflowNode("start", "trigger.manual"),
                    WorkflowNode("source", "source.repo", json.createObjectNode().put("url", other)),
                ), edges = listOf(WorkflowEdge("e1", Endpoint("start", "trigger"), Endpoint("source", "trigger")))))
            }.andExpect { status { isCreated() } }.andReturn().response.contentAsString)
            assertTrue(other in repositories())
            val runId = json.readTree(mockMvc.post("/api/workflows/${created.path("id").asText()}/run") {
                contentType = MediaType.APPLICATION_JSON
                content = """{"source":{"kind":"repo","url":"https://github.com/run-owner/run-repo"}}"""
            }.andExpect { status { isAccepted() } }.andReturn().response.contentAsString).path("runId").asText()
            assertTrue("https://github.com/run-owner/run-repo" in repositories())
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90)
            while (history.get(runId).status == RunStatus.RUNNING && System.nanoTime() < deadline) Thread.sleep(100)
            val message = history.get(runId).nodeRuns.firstOrNull { it.nodeId == "source" }?.error.orEmpty()
            assertFalse(message.contains("не подключён") || message.contains("разрешённ"), message)

            // Неподдерживаемые ссылки отклоняются понятным текстом.
            for (bad in listOf("http://github.com/a/b", "https://example.com/a/b", "https://127.0.0.1/a/b")) {
                mockMvc.post("/api/templates/release/copy") {
                    contentType = MediaType.APPLICATION_JSON
                    content = """{"repoUrl":"$bad"}"""
                }.andExpect {
                    status { isUnprocessableEntity() }
                    jsonPath("$.message") { value("Поддерживаются ссылки на GitHub, GitLab и Bitbucket по https") }
                }
            }
            assertFalse(repositories().any { "example.com" in it || "127.0.0.1" in it })

            // Автоматические запуски остаются строгими: неизвестный репозиторий не подключается.
            val trigger = json.createObjectNode().put("kind", "manual").apply {
                putObject("source").put("kind", "repo").put("url", "https://github.com/stranger/unknown")
            }
            assertThrows(workflow.nodes.InputRejected::class.java) { runs.start(requireNotNull(created.path("id").asText()), trigger) }
            assertFalse("https://github.com/stranger/unknown" in repositories())
        } finally {
            db.update("DELETE FROM repository_settings")
        }
    }

    @Test fun `parallel additions keep both repositories and are idempotent`() {
        val endpoint = "/api/settings/repositories"
        val urls = listOf("https://github.com/team/first", "https://github.com/team/second")
        val pool = Executors.newFixedThreadPool(2)
        val begin = CountDownLatch(1)
        try {
            mockMvc.put(endpoint) {
                contentType = MediaType.APPLICATION_JSON
                content = """{"repositories":[]}"""
            }.andExpect { status { isOk() } }
            val fixtures = urls.map { url ->
                pool.submit {
                    assertTrue(begin.await(5, TimeUnit.SECONDS))
                    mockMvc.post(endpoint) {
                        contentType = MediaType.APPLICATION_JSON
                        content = """{"url":"$url"}"""
                    }.andExpect { status { isOk() } }
                }
            }
            begin.countDown()
            fixtures.forEach { it.get(10, TimeUnit.SECONDS) }
            mockMvc.post(endpoint) {
                contentType = MediaType.APPLICATION_JSON
                content = """{"url":"${urls.first()}"}"""
            }.andExpect { status { isOk() } }
            val response = mockMvc.get(endpoint).andExpect { status { isOk() } }.andReturn().response
            assertEquals(urls.sorted(), json.readTree(response.contentAsString).path("repositories").map { it.asText() }.sorted())
        } finally {
            pool.shutdownNow()
            db.update("DELETE FROM repository_settings")
        }
    }

    @Test fun `run summaries use the captured repo instead of the current workflow`() {
        val workflow = store.create(Workflow(name = "Repository history", nodes = listOf(WorkflowNode("start", "trigger.manual"))))
        val workflowId = requireNotNull(workflow.id)
        val old = "https://github.com/team/original"
        val requestedUrl = "https://github.com/team/pull-request"
        val revision = json.createObjectNode().put("repoUrl", old)
        val first = RunRecord(UUID.randomUUID().toString(), workflowId, workflow.version,
            json.createObjectNode().put("kind", "manual"), RunStatus.SUCCESS, Instant.now(),
            nodeRuns = listOf(NodeRun("repository", NodeStatus.SUCCESS, output = mapOf("revision" to revision))))
        val second = RunRecord(UUID.randomUUID().toString(), workflowId, workflow.version,
            json.createObjectNode().put("kind", "webhook").apply {
                putObject("source").put("kind", "repo").put("url", requestedUrl)
            }, RunStatus.RUNNING, Instant.now())
        try {
            history.begin(first)
            history.begin(second)
            mockMvc.get("/api/runs/${first.id}").andExpect { jsonPath("$.repoUrl") { value(old) } }
            mockMvc.get("/api/runs/${second.id}").andExpect { jsonPath("$.repoUrl") { value(requestedUrl) } }
            mockMvc.get("/api/runs") { param("workflowId", workflowId) }.andExpect {
                jsonPath("$[*].repoUrl", org.hamcrest.Matchers.containsInAnyOrder(old, requestedUrl))
            }
        } finally {
            for (id in listOf(first.id, second.id)) {
                db.update("DELETE FROM run_events WHERE run_id = ?", id)
                db.update("DELETE FROM workflow_runs WHERE id = ?", id)
            }
        }
    }

    @Test fun `new built in templates have valid graphs and the designated nodes`() {
        val expected = mapOf(
            "zip-scan" to setOf("source.archive", "output.report"),
            "pr-new-telegram" to setOf("trigger.webhook", "logic.only-new", "notify.telegram"),
            "nightly-routes" to setOf("trigger.cron", "output.route-map"),
            "critical-approval" to setOf("logic.filter", REVIEW_WAIT_NODE),
        )
        for ((id, types) in expected) {
            val template = library.get(id)
            assertTrue(template.workflow.nodes.map { it.type }.containsAll(types), id)
            assertTrue(validator.validate(template.workflow).isEmpty(), id)
        }
    }

    @Test fun `template detail adds workflow to summary and catalog gives source description`() {
        val workflow = store.create(Workflow(name = "Основа", nodes = listOf(WorkflowNode("manual", "trigger.manual"))))
        val template = library.publish(PublishTemplate(requireNotNull(workflow.id), "Шаблон"))
        mockMvc.get("/api/templates/${template.id}").andExpect {
            status { isOk() }
            jsonPath("$.name") { value("Шаблон") }
            jsonPath("$.nodeCount") { value(1) }
            jsonPath("$.workflow.nodes[0].type") { value("trigger.manual") }
        }
        mockMvc.get("/api/nodes").andExpect {
            status { isOk() }
            jsonPath("$[?(@.type == 'source.repo')].description") { isNotEmpty() }
        }
    }

    @Test fun `report keeps analyzer findings and reads AI outputs directly without an output node`() {
        fun definition(name: String, port: PortSpec, category: NodeCategory = NodeCategory.ANALYZER): NodeDefinition =
            Mockito.mock(NodeDefinition::class.java).also {
                Mockito.`when`(it.type).thenReturn(name)
                Mockito.`when`(it.category).thenReturn(category)
                Mockito.`when`(it.outputs).thenReturn(listOf(port))
            }
        val service = ReportService(json, NodeRegistry(listOf(
            definition("analyzer.parse", PortSpec("model", PortType.PROJECT_MODEL)),
            definition("analyzer.secret", PortSpec("findings", PortType.FINDINGS)),
            definition("analyzer.sast", PortSpec("findings", PortType.FINDINGS)),
            definition("analyzer.sca", PortSpec("findings", PortType.FINDINGS)),
            definition("ai.explain", PortSpec("findings", PortType.FINDINGS), NodeCategory.AI),
        )), StaticListableBeanFactory().getBeanProvider(ReportExporter::class.java))
        val graph = Workflow(name = "SECRET", nodes = listOf(
            WorkflowNode("parse", "analyzer.parse"), WorkflowNode("scan", "analyzer.secret"),
            WorkflowNode("sast", "analyzer.sast"), WorkflowNode("sca", "analyzer.sca"), WorkflowNode("explain", "ai.explain"),
        ))
        val runs = listOf(
            NodeRun("parse", NodeStatus.SUCCESS),
            NodeRun("scan", NodeStatus.SUCCESS, output = mapOf("findings" to
                json.readTree("""[{"id":"same","fingerprint":"f1","severity":"HIGH","category":"SECRET"}]""")),
                coverage = json.createObjectNode().put("status", "COMPLETE"), rulesVersion = "secret-v1"),
            NodeRun("sast", NodeStatus.SUCCESS, output = mapOf("findings" to
                json.readTree("""[{"id":"same","fingerprint":"f2","severity":"LOW","category":"SAST"}]""")),
                coverage = json.createObjectNode().put("status", "COMPLETE"), rulesVersion = "sast-1"),
            NodeRun("sca", NodeStatus.SUCCESS, output = mapOf("findings" to json.readTree("[]")),
                coverage = json.createObjectNode().put("status", "COMPLETE")),
            NodeRun("explain", NodeStatus.SUCCESS, output = mapOf(
                "explanation" to json.readTree("""{"ai":{"status":"OK","model":"fixture-model","validator":{"responses":1}}}"""),
                "findings" to json.readTree("""
                    [{"id":"same","fingerprint":"f1","severity":"LOW","ai":{"status":"OK"}},
                     {"id":"same","fingerprint":"other","severity":"HIGH","ai":{"status":"OK"}}]
                """.trimIndent()),
            )),
        )
        val sha = "a".repeat(40)
        val record = RunRecord(
            "run", "workflow", 1, json.createObjectNode().put("commitSha", sha), RunStatus.SUCCESS, Instant.now(),
            coverageStatus = "COMPLETE", counts = mapOf("CRITICAL" to 0), commitsVerified = true,
            rulesVersions = runs.mapNotNull(NodeRun::rulesVersion).toSet(),
        )
        val report = requireNotNull(service.make(record, graph, runs, "COMPLETE", sha))
        assertEquals(listOf("scan", "sast", "sca"), service.scans(graph, runs).map { it.nodeId })
        assertEquals("sast-1+secret-v1", report.path("rulesVersion").asText())
        assertEquals(sha, report.path("inputHash").asText())
        assertEquals(setOf("scan", "sast", "sca"), report.path("coverage").path("byAnalyzer").fieldNames().asSequence().toSet())
        assertEquals("fixture-model", report.at("/ai/model").asText())
        assertEquals(1, report.at("/ai/validator/responses").asInt())
        assertEquals(2, report.path("findings").size())
        assertEquals("HIGH", report.at("/findings/0/severity").asText())
        assertEquals("OK", report.at("/findings/0/ai/status").asText())
        assertFalse(report.path("findings")[1].has("ai"))
        val completed = record.copy(report = report)
        assertEquals(GateDecision(true, "PASS"), CiGate.decide(completed, sha, "secret-v1+sast-1"))
        assertEquals(GateDecision(false, "RULES_VERSION_MISMATCH"), CiGate.decide(completed, sha, "secret-v1+sast-2"))
    }

    @Test fun `workflow secret is encrypted and retained on masked update`() {
        val secret = "12345:abcdefghijklmnopqrstuvwxyz"
        val raw = Workflow(name = "Telegram", nodes = listOf(
            WorkflowNode("telegram", "notify.telegram", json.createObjectNode().put("token", secret)),
        ))
        val created = store.create(raw)
        val id = requireNotNull(created.id)
        assertEquals(Redaction.MASK, created.nodes.single().params.path("token").asText())
        val ciphertext = db.queryForObject("SELECT payload FROM workflows WHERE id = ?", String::class.java, id)
        assertFalse(ciphertext.orEmpty().contains(secret))
        val saved = store.update(id, created.copy(name = "Edited"))
        assertEquals(2L, saved.version)
        assertEquals(secret, store.unlocked(id).nodes.single().params.path("token").asText())
        assertThrows(Conflict::class.java) { store.update(id, created) }
    }

    @Test fun `publication and launching recheck a previously stored graph`() {
        val source = store.create(Workflow(name = "Template", nodes = listOf(WorkflowNode("start", "trigger.manual"))))
        val id = requireNotNull(source.id)
        val invalid = source.copy(nodes = listOf(WorkflowNode("alien", "unknown.node")))
        db.update("UPDATE workflows SET payload = ? WHERE id = ?", json.writeValueAsString(invalid), id)
        assertThrows(InvalidGraph::class.java) { library.publish(PublishTemplate(id, "Broken")) }
        assertThrows(InvalidGraph::class.java) { runs.start(id, json.createObjectNode().put("kind", "manual")) }
        assertTrue(generatedErrors(invalid, validator, registry).any { it.code == "UNKNOWN_NODE" })
        assertFalse(library.list().any { it.name == "Broken" })
    }

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun config(registry: DynamicPropertyRegistry) {
            val data = Files.createTempDirectory("codeguard-test")
            registry.add("workflow.data-dir") { data.toString() }
            registry.add("APP_SECRETS_KEY") { Base64.getEncoder().encodeToString(ByteArray(32) { 17 }) }
        }
    }
}

@TestConfiguration(proxyBeanMethods = false)
class FailureNotificationFixture {
    val releaseSlot = CompletableDeferred<Unit>()

    @Bean
    fun holdSlot(): NodeDefinition = object : NodeDefinition {
        override val type = "test.hold-slot"
        override val title = "Execution slot fixture"
        override val category = NodeCategory.LOGIC
        override val inputs = emptyList<PortSpec>()
        override val outputs = emptyList<PortSpec>()
        override val paramsSchema = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode()

        override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
            releaseSlot.await()
            return NodeOutput(emptyMap())
        }
    }

    @Bean
    fun fixtureDelivery(): NodeDefinition = object : NodeDefinition {
        override val type = "test.failure-notification"
        override val title = "Failure notification fixture"
        override val category = NodeCategory.OUTPUT
        override val inputs = listOf(PortSpec("in", PortType.ANY))
        override val outputs = emptyList<PortSpec>()
        override val paramsSchema = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode()
        override val notifyOnFailure = true

        override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput {
            check(ctx.coverageStatus == "FAILED")
            ctx.log(requireNotNull(ctx.failureReason))
            return NodeOutput(emptyMap())
        }
    }
}
