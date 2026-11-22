package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import workflow.engine.RunStatus
import java.time.Instant
import java.util.UUID

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:pdfreport;DB_CLOSE_DELAY=-1",
    "workflow.data-dir=build/tmp/pdf-report-data",
])
@AutoConfigureMockMvc
class ReportPdfEndpointTest @Autowired constructor(
    private val history: RunStore,
    private val json: ObjectMapper,
    private val mockMvc: MockMvc,
) {
    @Test fun `report pdf is an attachment for a known run and 404 for an unknown one`() {
        val id = UUID.randomUUID().toString()
        history.begin(RunRecord(id, UUID.randomUUID().toString(), 1, json.createObjectNode().put("kind", "manual"),
            RunStatus.SUCCESS, Instant.parse("2026-01-01T00:00:00Z"), finishedAt = Instant.parse("2026-01-01T00:01:00Z"),
            report = json.valueToTree(mapOf("runId" to id, "coverage" to mapOf("status" to "COMPLETE"), "findings" to listOf(
                mapOf("id" to "f1", "category" to "SECRET", "class" to "password", "severity" to "HIGH",
                    "path" to "Config.kt", "line" to 1, "secretMasked" to "Zx****")))),
            workflowName = "demo"))
        val bytes = mockMvc.get("/api/runs/$id/report.pdf").andExpect {
            status { isOk() }
            content { contentTypeCompatibleWith("application/pdf") }
            header { string("Content-Disposition", org.hamcrest.Matchers.containsString("report-${id.take(8)}.pdf")) }
        }.andReturn().response.contentAsByteArray
        assertEquals("%PDF", String(bytes, 0, 4, Charsets.ISO_8859_1))
        mockMvc.get("/api/runs/${UUID.randomUUID()}/report.pdf").andExpect { status { isNotFound() } }
    }
}
