package workflow.analyzers.report

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.pdfbox.Loader
import org.apache.pdfbox.rendering.PDFRenderer
import org.apache.pdfbox.text.PDFTextStripper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import javax.imageio.ImageIO

class PdfReportTest {
    private val json = ObjectMapper()
    private val rawSecret = "Zx9kQ2mLp0wRAWSECRET"

    private fun report(status: String = "PARTIAL") = json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(mapOf(
        "runId" to "0123456789abcdef", "rulesVersion" to "rules-1", "inputHash" to "a".repeat(40),
        "coverage" to mapOf("status" to status, "byAnalyzer" to mapOf(
            "sast" to mapOf("status" to status, "filesAnalyzed" to 12, "rulesApplied" to listOf("sql-injection", "tls-verification"),
                "filesSkipped" to listOf(mapOf("path" to "src/Big.kt", "line" to 3, "reason" to "Файл слишком большой")),
                "unresolved" to emptyList<Any>()))),
        "findings" to listOf(
            mapOf("id" to "s1", "category" to "SECRET", "class" to "password", "severity" to "HIGH", "path" to "Config.kt", "line" to 4,
                "secretMasked" to "Zx****", "description" to "password = \"$rawSecret\"", "title" to rawSecret,
                "evidence" to listOf(mapOf("path" to "Config.kt", "line" to 4, "note" to rawSecret)),
                "ai" to mapOf("status" to "OK", "impact" to rawSecret)),
            mapOf("id" to "q1", "category" to "SAST", "class" to "sql-injection", "severity" to "CRITICAL", "path" to "src/Repo.kt",
                "line" to 10, "endLine" to 12, "title" to "SQL-инъекция в запросе", "description" to "Параметр попадает в запрос без экранирования.",
                "remediation" to "Используйте параметризованный запрос.",
                "evidence" to listOf(mapOf("path" to "src/Api.kt", "line" to 5, "note" to "источник"), mapOf("path" to "src/Repo.kt", "line" to 10))),
        ),
        "ai" to mapOf("status" to "OK", "model" to "m", "summary" to "Сначала закройте SQL-инъекцию.", "priorities" to listOf("q1", "s1")),
    ))

    private fun text(bytes: ByteArray) = Loader.loadPDF(bytes).use { PDFTextStripper().getText(it) }

    @Test fun `pdf is produced with Cyrillic text, page numbers and no raw secret`() {
        val meta = json.createObjectNode().put("workflowName", "Проверка репозитория").put("finishedAt", "2026-01-01T10:00:00Z")
            .put("source", "ZIP-архив")
        val bytes = DefaultReportExporter(json).pdf(report(), meta)!!
        assertEquals("%PDF", String(bytes, 0, 4, Charsets.ISO_8859_1))
        Loader.loadPDF(bytes).use { assertTrue(it.numberOfPages >= 1) }
        val extracted = text(bytes)
        assertTrue(extracted.contains(PRODUCT_NAME.uppercase()))
        assertTrue(extracted.contains("Отчёт по безопасности"))
        assertTrue(extracted.contains("PARTIAL"))
        assertTrue(extracted.contains("src/Big.kt:3"))
        assertTrue(extracted.contains("Zx****"))
        assertTrue(extracted.contains("Страница 1 из"))
        assertTrue(extracted.contains("Индекс безопасности: 90"))
        assertFalse(extracted.contains(rawSecret))
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains(rawSecret))
    }

    @Test fun `pdf never shows absolute or parent paths`() {
        val r = report().deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>()
        val list = r.withArray("findings")
        list.add(json.createObjectNode().put("id", "a1").put("category", "SAST").put("class", "tls-verification")
            .put("severity", "LOW").put("path", "C:\\Users\\bob\\proj\\A.kt").put("line", 1))
        list.add(json.createObjectNode().put("id", "a2").put("category", "SAST").put("class", "tls-verification")
            .put("severity", "LOW").put("path", "../outside/B.kt").put("line", 2))
        val extracted = text(DefaultReportExporter(json).pdf(r, null)!!)
        assertFalse(extracted.contains("bob"))
        assertFalse(extracted.contains("outside"))
        assertTrue(extracted.contains("путь вне проекта скрыт"))
    }

    @Test fun `pdf is deterministic and handles empty and long reports`() {
        val exporter = DefaultReportExporter(json)
        val meta = json.createObjectNode().put("finishedAt", "2026-01-01T10:00:00Z")
        assertArrayEquals(exporter.pdf(report(), meta), exporter.pdf(report(), meta))
        val empty = json.readTree("""{"runId":"x","coverage":{"status":"COMPLETE"},"findings":[]}""")
        assertTrue(text(exporter.pdf(empty, null)!!).contains("Находок нет"))
        val many = report().deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>()
        val list = many.withArray("findings")
        repeat(80) { i ->
            list.add(json.createObjectNode().put("id", "m$i").put("category", "SAST").put("class", "tls-verification")
                .put("severity", "MEDIUM").put("path", "very/long/" + "dir/".repeat(20) + "File$i.kt").put("line", i + 1)
                .put("description", "Длинное описание ".repeat(40)).put("remediation", "Исправить"))
        }
        Loader.loadPDF(exporter.pdf(many, meta)!!).use { assertTrue(it.numberOfPages > 3) }
    }

    private fun withLanguages() = report().deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>().apply {
        val a = putArray("languages")
        a.addObject().put("name", "Kotlin").put("files", 12).put("secret", true).put("sca", true).put("sast", true)
            .put("note", "анализируется (SECRET, SCA, SAST)")
        a.addObject().put("name", "JavaScript").put("files", 1).put("secret", true).put("sca", false).put("sast", false)
            .put("note", "SECRET: да; SAST и SCA: не поддерживается")
        a.addObject().put("name", "Shell").put("files", 3).put("secret", true).put("sca", false).put("sast", false)
            .put("note", "SECRET: да; SAST не применим (скрипты)")
    }

    @Test fun `pdf has project languages block with Cyrillic and skips it when absent`() {
        val exporter = DefaultReportExporter(json)
        val meta = json.createObjectNode().put("finishedAt", "2026-01-01T10:00:00Z")
        val extracted = text(exporter.pdf(withLanguages(), meta)!!)
        assertTrue(extracted.contains("Языки проекта"), extracted)
        assertTrue(extracted.contains("не поддерживается"))
        assertTrue(extracted.contains("JavaScript"))
        assertTrue(extracted.contains("Kotlin"))
        assertFalse(extracted.contains("?"), "Кириллица должна рендериться без подмены на «?»")
        assertArrayEquals(exporter.pdf(withLanguages(), meta), exporter.pdf(withLanguages(), meta))
        assertFalse(text(exporter.pdf(report(), meta)!!).contains("Языки проекта"))
    }

    /** Рендер страниц в PNG для визуальной проверки: PDF_SAMPLE_DIR=каталог. */
    @Test fun `optional sample render`() {
        val dir = System.getenv("PDF_SAMPLE_DIR") ?: return
        val bytes = DefaultReportExporter(json).pdf(withLanguages(), json.createObjectNode().put("workflowName", "Проверка репозитория")
            .put("finishedAt", "2026-01-01T10:00:00Z").put("source", "ZIP-архив"))!!
        File(dir).mkdirs()
        File(dir, "sample.pdf").writeBytes(bytes)
        Loader.loadPDF(bytes).use { ImageIO.write(PDFRenderer(it).renderImageWithDPI(0, 100f), "png", File(dir, "sample-page1.png")) }
        Loader.loadPDF(bytes).use { if (it.numberOfPages > 1) ImageIO.write(PDFRenderer(it).renderImageWithDPI(1, 100f), "png", File(dir, "sample-page2.png")) }
    }
}
