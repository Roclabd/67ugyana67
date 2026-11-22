package workflow.app

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

@SpringBootTest(properties = ["spring.datasource.url=jdbc:h2:mem:spa;DB_CLOSE_DELAY=-1"])
@AutoConfigureMockMvc
class SpaFallbackTest @Autowired constructor(private val mockMvc: MockMvc) {
    private val html = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    private fun page(path: String) = mockMvc.get(path) { header("Accept", html) }.andExpect {
        status { isOk() }
        content { string(org.hamcrest.Matchers.containsString("id=\"root\"")) }
    }

    @Test fun `root and client routes return the application shell`() {
        mockMvc.get("/") { header("Accept", html) }.andExpect { forwardedUrl("index.html") }
        for (path in listOf("/settings", "/projects", "/templates", "/runs/abc/report", "/runs/abc")) page(path)
    }

    @Test fun `unknown api paths keep a real 404 even for browsers`() {
        mockMvc.get("/api/unknown") { header("Accept", html) }.andExpect { status { isNotFound() } }
        mockMvc.get("/api/unknown") { accept = MediaType.APPLICATION_JSON }.andExpect { status { isNotFound() } }
        mockMvc.get("/api/runs/x/report.json") { header("Accept", html) }.andExpect { status { isNotFound() } }
    }

    @Test fun `missing assets and non html requests return 404`() {
        mockMvc.get("/assets/missing.js") { header("Accept", html) }.andExpect { status { isNotFound() } }
        mockMvc.get("/assets/missing.js") { accept = MediaType.ALL }.andExpect { status { isNotFound() } }
        mockMvc.get("/settings") { accept = MediaType.APPLICATION_JSON }.andExpect { status { isNotFound() } }
    }

    @Test fun `existing api endpoints are not shadowed`() {
        mockMvc.get("/api/nodes") { header("Accept", html + ",application/json") }.andExpect { status { isOk() } }
        mockMvc.get("/api/runs") { accept = MediaType.APPLICATION_JSON }.andExpect { status { isOk() } }
    }

    @Test fun `route detection ignores api, extensions and other methods`() {
        val route = SpaFallback.SpaResolver::isRoute
        assertTrue(route("GET", "runs/1/report", listOf("text/html")))
        assertFalse(route("GET", "api/runs", listOf("text/html")))
        assertFalse(route("GET", "api", listOf("text/html")))
        assertFalse(route("GET", "assets/a.js", listOf("text/html")))
        assertFalse(route("POST", "settings", listOf("text/html")))
        assertFalse(route("GET", "settings", listOf("*/*")))
    }
}
