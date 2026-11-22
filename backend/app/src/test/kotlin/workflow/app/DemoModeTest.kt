package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockMultipartFile
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.delete
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.multipart
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.put
import workflow.engine.*

private const val DEMO_REPO = "https://github.com/acme/app"

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:demomode;DB_CLOSE_DELAY=-1",
    "APP_PUBLIC_DEMO=true",
    "APP_ALLOWED_HOSTS=localhost",
    "APP_PUBLIC_DEMO_REPOS=$DEMO_REPO",
    "APP_PUBLIC_DEMO_RUNS_PER_HOUR=3",
    "APP_PUBLIC_DEMO_MAX_CONCURRENT=50",
    "APP_SECRETS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
])
@AutoConfigureMockMvc
class DemoModeTest @Autowired constructor(
    private val mvc: MockMvc,
    private val json: ObjectMapper,
) {
    private fun copyRelease(body: String = """{"repoUrl":"$DEMO_REPO"}"""): JsonNode {
        val response = mvc.post("/api/templates/release/copy") {
            contentType = MediaType.APPLICATION_JSON; content = body
        }.andReturn().response
        assertEquals(201, response.status, response.contentAsString)
        return json.readTree(response.contentAsString)
    }

    @Test fun `meta reports the demo flag`() {
        val meta = json.readTree(mvc.get("/api/meta").andReturn().response.contentAsString)
        assertTrue(meta.path("publicDemo").asBoolean())
    }

    @Test fun `settings telegram import and workflow edits are blocked`() {
        fun blocked(status: Int, body: String) {
            assertEquals(403, status, body)
            assertTrue(body.contains("Недоступно в демо-режиме"), body)
        }
        fun check(call: () -> org.springframework.mock.web.MockHttpServletResponse) {
            val r = call(); blocked(r.status, r.getContentAsString(Charsets.UTF_8))
        }
        check { mvc.put("/api/settings/llm") { contentType = MediaType.APPLICATION_JSON; content = "{}" }.andReturn().response }
        check { mvc.put("/api/settings/repositories") { contentType = MediaType.APPLICATION_JSON; content = """{"repositories":[]}""" }.andReturn().response }
        check { mvc.post("/api/settings/repositories") { contentType = MediaType.APPLICATION_JSON; content = """{"url":"$DEMO_REPO"}""" }.andReturn().response }
        check { mvc.put("/api/integrations/telegram") { contentType = MediaType.APPLICATION_JSON; content = """{"token":"x"}""" }.andReturn().response }
        check { mvc.post("/api/integrations/telegram/test") { contentType = MediaType.APPLICATION_JSON; content = "{}" }.andReturn().response }
        check { mvc.post("/api/workflows/import.yaml") { contentType = MediaType.parseMediaType("text/yaml"); content = "name: x" }.andReturn().response }
        check { mvc.post("/api/workflows") { contentType = MediaType.APPLICATION_JSON; content = """{"name":"x"}""" }.andReturn().response }
        check { mvc.put("/api/workflows/any") { contentType = MediaType.APPLICATION_JSON; content = """{"name":"x"}""" }.andReturn().response }
        check { mvc.delete("/api/workflows/any").andReturn().response }
        check { mvc.post("/api/ci/workflows/any/run") { contentType = MediaType.APPLICATION_JSON; content = "{}" }.andReturn().response }
        check { mvc.post("/api/webhooks/any").andReturn().response }
        check { mvc.post("/api/workflows/generate") { contentType = MediaType.APPLICATION_JSON; content = """{"text":"x"}""" }.andReturn().response }
    }

    @Test fun `settings reads stay available and never reveal secrets`() {
        val telegram = mvc.get("/api/integrations/telegram").andReturn().response
        assertEquals(200, telegram.status)
        assertEquals("", json.readTree(telegram.contentAsString).path("chatId").asText())
        assertEquals(200, mvc.get("/api/settings/llm").andReturn().response.status)
        assertEquals(200, mvc.get("/api/settings/repositories").andReturn().response.status)
    }

    @Test fun `repository list is fixed to the demo allowlist`() {
        val repos = json.readTree(mvc.get("/api/settings/repositories").andReturn().response.contentAsString)
        assertEquals(listOf(DEMO_REPO), repos.path("repositories").map { it.asText() })
    }

    @Test fun `copy rejects a foreign repository and a recipient`() {
        val foreign = mvc.post("/api/templates/release/copy") {
            contentType = MediaType.APPLICATION_JSON; content = """{"repoUrl":"https://github.com/evil/repo"}"""
        }.andReturn().response
        assertEquals(422, foreign.status)
        val recipient = mvc.post("/api/templates/daily-secrets/copy") {
            contentType = MediaType.APPLICATION_JSON; content = """{"repoUrl":"$DEMO_REPO","recipient":"a@b.c"}"""
        }.andReturn().response
        assertEquals(422, recipient.status)
    }

    @Test fun `copied template has no notification nodes`() {
        val copy = copyRelease()
        assertTrue(copy.path("nodes").none { it.path("type").asText().startsWith("notify.") })
        assertTrue(copy.path("nodes").any { it.path("type").asText() == "source.repo" })
    }

    @Test fun `run on allowlisted repository starts and foreign repository is rejected`() {
        val id = copyRelease().path("id").asText()
        val ok = mvc.post("/api/workflows/$id/run") {
            contentType = MediaType.APPLICATION_JSON
            header("X-Forwarded-For", "203.0.113.10")
            content = """{"source":{"kind":"repo","url":"$DEMO_REPO"}}"""
        }.andReturn().response
        assertTrue(ok.status in setOf(202, 409), ok.contentAsString) // 409: слоты заняты соседними тестами
        val foreign = mvc.post("/api/workflows/$id/run") {
            contentType = MediaType.APPLICATION_JSON
            header("X-Forwarded-For", "203.0.113.11")
            content = """{"source":{"kind":"repo","url":"https://github.com/evil/repo"}}"""
        }.andReturn().response
        assertEquals(422, foreign.status)
    }

    @Test fun `runs are limited per client address`() {
        val id = copyRelease().path("id").asText()
        fun run(ip: String) = mvc.post("/api/workflows/$id/run") {
            contentType = MediaType.APPLICATION_JSON
            header("X-Forwarded-For", ip)
            content = """{"source":{"kind":"repo","url":"$DEMO_REPO"}}"""
        }.andReturn().response
        repeat(3) { assertNotEquals(429, run("198.51.100.7").status) }
        val limited = run("198.51.100.7")
        assertEquals(429, limited.status)
        assertTrue(limited.getContentAsString(Charsets.UTF_8).contains("Слишком много запусков"))
        assertNotEquals(429, run("198.51.100.8").status)
    }

    @Test fun `upload stays allowed`() {
        val response = mvc.multipart("/api/uploads") {
            file(MockMultipartFile("file", "a.zip", "application/zip", ByteArray(0)))
            header("X-Forwarded-For", "203.0.113.50")
        }.andReturn().response
        assertNotEquals(403, response.status)
    }
}

class DemoModeUnitTest {
    private fun demo(enabled: Boolean = true, ai: Boolean = true, aiPerHour: Int = 20, concurrent: Int = 2, hosts: String = "demo.example") =
        DemoMode(enabled, "", ai, aiPerHour, 6, concurrent, "127.0.0.1", hosts)

    private fun node(id: String, type: String) = WorkflowNode(id, type)
    private fun edge(from: String, out: String, to: String, input: String) =
        WorkflowEdge("${from}_${out}_${to}_$input", Endpoint(from, out), Endpoint(to, input))

    private val graph = Workflow(name = "w", nodes = listOf(
        node("start", "trigger.manual"), node("src", "source.repo"), node("sast", "analyzer.sast"),
        node("ai", "ai.explain"), node("report", "output.report"), node("tg", "notify.telegram"),
    ), edges = listOf(
        edge("start", "trigger", "src", "trigger"), edge("src", "workspace", "sast", "workspace"),
        edge("sast", "findings", "ai", "findings"), edge("ai", "findings", "report", "findings"),
        edge("ai", "explanation", "report", "explanation"), edge("report", "report", "tg", "report"),
    ))

    @Test fun `demo requires allowed hosts`() {
        assertThrows(IllegalArgumentException::class.java) { demo(hosts = "") }
        demo(enabled = false, hosts = "")
    }

    @Test fun `disabled demo changes nothing`() {
        val off = demo(enabled = false)
        assertTrue(off.allows("PUT", "/api/settings/llm"))
        assertSame(graph, off.sanitize(graph))
    }

    @Test fun `sanitize strips notifications and keeps ai while the limit lasts`() {
        val clean = demo().sanitize(graph)
        assertTrue(clean.nodes.none { it.type.startsWith("notify.") })
        assertTrue(clean.nodes.any { it.type == "ai.explain" })
        assertTrue(clean.edges.none { it.from.node == "tg" || it.to.node == "tg" })
    }

    @Test fun `ai is bypassed when disabled or over the hourly limit`() {
        val off = demo(ai = false).sanitize(graph)
        assertTrue(off.nodes.none { it.type == "ai.explain" })
        assertTrue(off.edges.any { it.from.node == "sast" && it.to.node == "report" && it.to.port == "findings" })
        val limited = demo(aiPerHour = 1)
        assertTrue(limited.sanitize(graph).nodes.any { it.type == "ai.explain" })
        assertTrue(limited.sanitize(graph).nodes.none { it.type == "ai.explain" })
    }

    @Test fun `concurrent runs are capped and released`() {
        val d = demo(concurrent = 1)
        val request = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "198.51.100.1") }
        val release = d.claimRun(request)
        assertThrows(RateLimited::class.java) { d.claimRun(MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "198.51.100.2") }) }
        release()
        d.claimRun(MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "198.51.100.3") })()
    }

    @Test fun `forwarded address is trusted only from the proxy`() {
        val d = demo()
        val viaProxy = MockHttpServletRequest().apply { remoteAddr = "127.0.0.1"; addHeader("X-Forwarded-For", "6.6.6.6, 203.0.113.9") }
        assertEquals("203.0.113.9", d.clientIp(viaProxy))
        val direct = MockHttpServletRequest().apply { remoteAddr = "198.51.100.4"; addHeader("X-Forwarded-For", "1.2.3.4") }
        assertEquals("198.51.100.4", d.clientIp(direct))
    }
}

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:demooff;DB_CLOSE_DELAY=-1"])
@AutoConfigureMockMvc
class DemoModeOffTest @Autowired constructor(private val mvc: MockMvc, private val json: ObjectMapper) {
    @Test fun `without the flag nothing is blocked`() {
        val meta = json.readTree(mvc.get("/api/meta").andReturn().response.contentAsString)
        assertFalse(meta.path("publicDemo").asBoolean())
        val put = mvc.put("/api/settings/repositories") {
            contentType = MediaType.APPLICATION_JSON; content = """{"repositories":["https://github.com/acme/app"]}"""
        }.andReturn().response
        assertEquals(200, put.status)
    }
}
