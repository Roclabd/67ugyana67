package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.web.MockMultipartFile
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.multipart
import workflow.engine.RunStatus
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:quality;DB_CLOSE_DELAY=-1",
    "workflow.data-dir=build/quality-test-data",
])
@AutoConfigureMockMvc
class QualityScenarioTest @Autowired constructor(
    private val mockMvc: MockMvc,
    private val library: TemplateLibrary,
    private val runs: RunService,
    private val history: RunStore,
    private val json: ObjectMapper,
) {
    private fun zip(files: Map<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip -> files.forEach { (name, text) -> zip.putNextEntry(ZipEntry(name)); zip.write(text.toByteArray()); zip.closeEntry() } }
        return out.toByteArray()
    }

    @Test fun `zip with mixed project runs through the quality template and reopens from history`() {
        val upload = mockMvc.multipart("/api/uploads") {
            file(MockMultipartFile("file", "p.zip", "application/zip", zip(mapOf(
                "app/Demo.kt" to "fun result(value: Int): Int = vlaue + 1\nfun nextValue(value: Int): Int = value +\n",
                "tools/util.py" to "def append_tag(tag, tags=[]):\n    tags.append(tag)\n    return tags\n",
                "web/main.js" to "function gardenCapacity(configured) {\n    return configured || 12;\n}\n",
                "README.md" to "# hi",
            ))))
        }.andExpect { status { isCreated() } }.andReturn().response.contentAsString
        val uploadId = json.readTree(upload).path("uploadId").asText()

        val workflow = library.copy("code-quality", CopyTemplate(uploadId = uploadId))
        val trigger = json.createObjectNode().put("kind", "manual").apply { putObject("source").put("kind", "upload").put("uploadId", uploadId) }
        val ticket = runs.start(requireNotNull(workflow.id), trigger)
        var run = history.get(ticket.id)
        repeat(300) { if (run.status == RunStatus.RUNNING) { Thread.sleep(100); run = history.get(ticket.id) } }
        assertEquals(RunStatus.SUCCESS, run.status, run.error)

        // «Повторное открытие из истории»: тот же ответ читается из хранилища.
        val body = mockMvc.get("/api/runs/${ticket.id}").andExpect { status { isOk() } }.andReturn().response.contentAsString
        val quality = json.readTree(body).path("report").path("quality")
        assertEquals(1, quality.path("version").asInt())
        assertEquals("ISSUES", quality.path("status").asText())
        val kinds = quality.path("diagnostics").map { it.path("kind").asText() }.toSet()
        assertTrue(kinds.containsAll(setOf("syntax", "functional-defect")), kinds.toString())
        val first = quality.path("diagnostics").first { it.path("rule").asText() == "python.defect.mutable-default" }
        assertEquals("tools/util.py", first.path("path").asText())
        assertEquals(1, first.path("line").asInt())
        // Безопасность не затронута: находок нет, блок не попадает в выгрузку авторов набора.
        assertEquals(0, json.readTree(body).path("report").path("findings").size())
        val organizer = mockMvc.get("/api/runs/${ticket.id}/report.json").andReturn().response.contentAsString
        assertFalse(organizer.contains("quality"))
    }

    @Test fun `quality node is outside the analyzer category and the template is listed`() {
        val ids = json.readTree(mockMvc.get("/api/templates").andReturn().response.contentAsString).map { it.path("id").asText() }
        assertTrue("code-quality" in ids)
        val nodes = json.readTree(mockMvc.get("/api/nodes").andReturn().response.contentAsString)
        assertEquals("OUTPUT", nodes.first { it.path("type").asText() == "analyzer.quality" }.path("category").asText())
    }
}
