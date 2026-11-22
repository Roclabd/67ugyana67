package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.web.MockMultipartFile
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.multipart
import workflow.engine.RunStatus
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Проект на любом языке не должен виснуть: секреты находятся везде, SCA и SAST честно сообщают, что пропущено. */
@SpringBootTest(properties = [
    "spring.datasource.url=jdbc:h2:mem:multilang;DB_CLOSE_DELAY=-1",
    "workflow.data-dir=build/multilang-test-data",
])
@AutoConfigureMockMvc
class MultiLanguageScanTest @Autowired constructor(
    private val mockMvc: MockMvc,
    private val library: TemplateLibrary,
    private val runs: RunService,
    private val history: RunStore,
    private val json: ObjectMapper,
) {
    private fun zip(files: Map<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip -> files.forEach { (name, bytes) -> zip.putNextEntry(ZipEntry(name)); zip.write(bytes); zip.closeEntry() } }
        return out.toByteArray()
    }

    private fun text(vararg files: Pair<String, String>) = zip(files.associate { it.first to it.second.toByteArray() })

    private data class Scanned(val millis: Long, val status: RunStatus, val report: JsonNode?)

    private fun scan(archive: ByteArray): Scanned {
        val upload = mockMvc.multipart("/api/uploads") {
            file(MockMultipartFile("file", "p.zip", "application/zip", archive))
        }.andExpect { status { isCreated() } }.andReturn().response.contentAsString
        val uploadId = json.readTree(upload).path("uploadId").asText()
        val workflow = library.copy("zip-scan", CopyTemplate(uploadId = uploadId))
        val trigger = json.createObjectNode().put("kind", "manual").apply {
            putObject("source").put("kind", "upload").put("uploadId", uploadId)
        }
        val started = System.nanoTime()
        val ticket = runs.start(requireNotNull(workflow.id), trigger)
        var run = history.get(ticket.id)
        while (run.status == RunStatus.RUNNING && System.nanoTime() - started < 10_000_000_000L) {
            Thread.sleep(50)
            run = history.get(ticket.id)
        }
        val millis = (System.nanoTime() - started) / 1_000_000
        assertNotEquals(RunStatus.RUNNING, run.status, "Запуск завис: ${run.nodeRuns.map { it.nodeId to it.status }}")
        assertTrue(millis < 10_000, "Запуск занял $millis мс")
        return Scanned(millis, run.status, run.report)
    }

    private fun Scanned.coverage(node: String): JsonNode = report!!.path("coverage").path("byAnalyzer").path(node)

    private fun Scanned.reasons(node: String): List<String> =
        coverage(node).path("filesSkipped").map { it.path("reason").asText() }

    private fun Scanned.secretPaths(): Set<String> =
        report!!.path("findings").filter { it.path("category").asText() == "SECRET" }.map { it.path("path").asText() }.toSet()

    @Test fun `java maven project finishes quickly with honest partial coverage`() {
        val result = scan(text(
            "backend/pom.xml" to "<project><dependencies><dependency><groupId>org.springframework</groupId>" +
                "<artifactId>spring-core</artifactId><version>5.3.0</version></dependency></dependencies></project>",
            "backend/src/main/java/app/A.java" to "package app;\nclass A { void run() {} }\n",
            "backend/src/main/java/app/B.java" to "package app;\nclass B { }\n",
            "backend/src/main/java/app/C.java" to "package app;\nclass C { }\n",
            "backend/src/main/resources/application.yml" to "spring:\n  datasource:\n    password: \"Zk9mQ2vL8pZr4tW7\"\n",
        ))
        assertTrue("backend/src/main/resources/application.yml" in result.secretPaths(), result.secretPaths().toString())
        assertEquals("PARTIAL", result.coverage("sca").path("status").asText())
        assertTrue("Maven (pom.xml) не поддерживается — анализируются Gradle Kotlin DSL" in result.reasons("sca"),
            result.reasons("sca").toString())
        assertEquals("PARTIAL", result.coverage("sast").path("status").asText())
        assertTrue("Java-файлы не анализируются (3 файла)" in result.reasons("sast"), result.reasons("sast").toString())
        val java = result.report!!.path("languages").first { it.path("name").asText() == "Java" }
        assertEquals(3, java.path("files").asInt())
        assertEquals("PARTIAL", result.report.path("coverage").path("status").asText())
    }

    @Test fun `cpp project finds secrets in source and ini config`() {
        val result = scan(text(
            "src/main.cpp" to "#include <string>\nconst char* key = \"AKIAIOSFODNN7EXAMPLE\";\nint main() { return 0; }\n",
            "conf/config.ini" to "[db]\nhost=localhost\npassword=Tr0ub4dor3x\n",
            "conanfile.txt" to "[requires]\nzlib/1.2.13\n",
        ))
        assertEquals(setOf("src/main.cpp", "conf/config.ini"), result.secretPaths())
        assertTrue(result.reasons("sca").any { "Conan" in it && "не поддерживается" in it }, result.reasons("sca").toString())
        assertTrue(result.reasons("sast").any { "C++-файлы не анализируются (1 файл)" == it }, result.reasons("sast").toString())
    }

    @Test fun `python project reports requirements as unsupported and finds the settings secret`() {
        val result = scan(text(
            "requirements.txt" to "flask==2.0.0\n",
            "app/settings.py" to "DEBUG = False\nSECRET_KEY = \"k9Zp2Xv7Qm4Lw8Rt\"\n",
        ))
        assertTrue("app/settings.py" in result.secretPaths(), result.secretPaths().toString())
        assertTrue(result.reasons("sca").any { it.startsWith("Python (requirements.txt) не поддерживается") })
        assertEquals("PARTIAL", result.coverage("sast").path("status").asText())
    }

    @Test fun `project without code and image only project complete without findings`() {
        val readme = scan(text("README.md" to "# Пустой проект\n"))
        assertEquals(0, readme.report!!.path("findings").size())
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4)
        val images = scan(zip(mapOf("a.png" to png, "fonts/b.ttf" to ByteArray(2000) { it.toByte() })))
        assertEquals(0, images.report!!.path("findings").size())
    }

    @Test fun `deeply nested long json string does not overflow the stack`() {
        val long = "x".repeat(200_000)
        val result = scan(text("data/big.json" to "{\"note\": \"$long\", \"other\": \"1\"}"))
        assertNotEquals(RunStatus.FAILED, result.status)
    }
}
