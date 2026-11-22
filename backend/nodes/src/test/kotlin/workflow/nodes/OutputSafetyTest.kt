package workflow.nodes

import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import workflow.engine.*
import java.io.ByteArrayOutputStream
import java.nio.file.Path

class OutputSafetyTest {
    private val json = ObjectMapper()
    private val output = OutputNodes(json, "", "", "", 587, "", "", "")
    private val context = object : NodeContext {
        override val runId = "test"
        override val nodeId = "output"
        override val params = json.createObjectNode()
        override val workspace: Path? = null
        override val trigger = json.createObjectNode()
        override val coverageStatus = "PARTIAL"
        override fun redact(message: String) = message.replace("raw-token", Redaction.MASK)
        override fun log(message: String) = Unit
        override fun emitProgress(percent: Int, note: String?) = Unit
    }

    @Test fun `findings survive unvalidated AI and verified explanations survive report assembly`() {
        val findings = listOf(mapOf("severity" to "HIGH", "path" to "src/main.kt", "title" to "Example"))
        val untrusted = output.notificationText(context,
            NodeInput(mapOf("findings" to findings, "explanation" to "unverified AI")))
        assertTrue(untrusted.contains("src/main.kt"))
        assertTrue(untrusted.contains("PARTIAL"))
        assertFalse(untrusted.contains("unverified AI"))

        val verified = object : ValidatedExplanation {
            override val text = "Проверенное объяснение raw-token"
            val ai = mapOf("status" to "OK", "model" to "fixture-model", "validator" to mapOf("responses" to 1))
        }
        val report = runBlocking {
            output.buildReport().run(context, NodeInput(mapOf("findings" to findings, "explanation" to verified)))
        }
        val notification = output.notificationText(context, NodeInput(report.ports))
        val reportJson = json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(report.ports["report"])
        assertEquals("fixture-model", reportJson.at("/ai/model").asText())
        assertEquals(1, reportJson.at("/ai/validator/responses").asInt())
        assertTrue(notification.contains("src/main.kt"))
        assertTrue(notification.contains("Проверенное объяснение"))
        assertFalse(notification.contains("raw-token"))
    }

    @Test fun `Telegram sends a compact card and keeps all findings in the attachment`() {
        val findings = (1..42).map {
            mapOf("severity" to "HIGH", "path" to "src/F$it.kt", "title" to "Example raw-token")
        }
        val input = NodeInput(mapOf("findings" to findings))
        val text = output.telegramMessage(context, input, "test-chat").getValue("text") as String
        val markdown = output.telegramMarkdown(context, input)
        assertTrue(text.contains("Подтверждённых находок: 42"))
        assertTrue(text.contains("F3.kt"))
        assertFalse(text.contains("F4.kt"))
        assertFalse(text.contains("F42.kt"))
        assertFalse(text.contains("raw-token"))
        assertTrue(markdown.contains("F42.kt"))
        assertFalse(markdown.contains("raw-token"))
        val body = PublicNetwork.telegramReportBody("test-chat", markdown)
        val multipart = ByteArrayOutputStream().also(body::writeTo).toString(Charsets.UTF_8)
        assertTrue(body.contentType.startsWith("multipart/form-data;"))
        assertTrue(multipart.contains("name=\"chat_id\"") && multipart.contains("test-chat"))
        assertTrue(multipart.contains("name=\"document\"; filename=\"report.md\"") && multipart.contains(markdown))
    }

    @Test fun `Telegram reports a failed attachment after the card was sent without leaking the token`() {
        val token = "123456:AAAA-secret-token-for-attachment-test"
        val sent = mutableListOf<String>()
        fun node(failCard: Boolean, failFile: Boolean) = OutputNodes(json, "", "", "", 587, "", "", "").also {
            it.telegramTransport = object : TelegramTransport {
                override fun message(token: String, body: String) {
                    if (failCard) throw IllegalStateException(token)
                    sent.add("card")
                }
                override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) {
                    if (failFile) throw IllegalStateException(token)
                    sent.add("file")
                }
            }
        }
        val withParams = object : NodeContext by context {
            override val params = json.createObjectNode().put("token", token).put("chatId", "42")
        }
        val input = NodeInput(emptyMap())
        runBlocking { node(false, false).telegram().run(withParams, input) }
        assertEquals(listOf("card", "file"), sent)

        sent.clear()
        val file = assertThrows(NodeFailure::class.java) { runBlocking { node(false, true).telegram().run(withParams, input) } }
        assertEquals(listOf("card"), sent)
        assertTrue(file.message!!.contains("карточка отправлена"))
        assertFalse(file.message!!.contains(token))

        sent.clear()
        val card = assertThrows(NodeFailure::class.java) { runBlocking { node(true, false).telegram().run(withParams, input) } }
        assertTrue(sent.isEmpty())
        assertTrue(card.message!!.contains("карточка не отправлена"))
        assertFalse(card.message!!.contains(token))
    }

    @Test fun `Telegram attachment is a PDF and falls back to markdown when generation fails`() {
        val token = "123456:AAAA-secret-token-for-attachment-test"
        class Sent(val filename: String, val contentType: String, val content: ByteArray)
        fun run(exporter: ReportExporter?, failFile: Boolean = false): List<Sent> {
            val sent = mutableListOf<Sent>()
            val node = OutputNodes(json, "", "", "", 587, "", "", "", exporter = exporter).also {
                it.telegramTransport = object : TelegramTransport {
                    override fun message(token: String, body: String) = Unit
                    override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) {
                        if (failFile) throw IllegalStateException(token)
                        sent.add(Sent(attachment.filename, attachment.contentType, attachment.content))
                    }
                }
            }
            val withParams = object : NodeContext by context {
                override val runId = "0123456789abcdef"
                override val params = json.createObjectNode().put("token", token).put("chatId", "42")
            }
            runBlocking { node.telegram().run(withParams, NodeInput(emptyMap())) }
            return sent
        }
        fun exporter(pdf: () -> ByteArray?) = object : ReportExporter {
            override fun json(report: com.fasterxml.jackson.databind.JsonNode) = report
            override fun markdown(report: com.fasterxml.jackson.databind.JsonNode) = "# md"
            override fun pdf(report: com.fasterxml.jackson.databind.JsonNode, meta: com.fasterxml.jackson.databind.JsonNode?) = pdf()
        }

        val ok = run(exporter { "%PDF-1.7 fake".toByteArray() }).single()
        assertEquals("report-01234567.pdf", ok.filename)
        assertEquals("application/pdf", ok.contentType)
        assertTrue(String(ok.content).startsWith("%PDF"))

        for (broken in listOf(exporter { throw IllegalStateException("boom") }, exporter { null }, exporter { "not a pdf".toByteArray() }, null)) {
            val fallback = run(broken).single()
            assertEquals("report.md", fallback.filename)
            assertEquals("text/markdown", fallback.contentType)
        }
        assertThrows(NodeFailure::class.java) { run(exporter { "%PDF-1.7".toByteArray() }, failFile = true) }
    }

    @Test fun `Telegram sorts risk before formatting and escapes dynamic fields`() {
        val configured = OutputNodes(json, "", "", "", 587, "", "", "", publicUrl = "https://demo.example/")
        val complete = object : NodeContext by context {
            override val workflowName = "Repair <Desk>"
            override val coverageStatus = "COMPLETE"
        }
        val findings = listOf(
            mapOf("severity" to "LOW", "category" to "SECRET", "title" to "Low priority"),
            mapOf("severity" to "MEDIUM", "category" to "SAST", "title" to "Code review"),
            mapOf("severity" to "HIGH", "category" to "SAST", "title" to "High priority"),
            mapOf("severity" to "CRITICAL", "category" to "SCA", "title" to "Critical <risk> & raw-token",
                "path" to "build<file>.gradle.kts", "line" to 31, "remediation" to "Обновите & проверьте raw-token"),
        )
        val payload = json.valueToTree<com.fasterxml.jackson.databind.JsonNode>(
            configured.telegramMessage(complete, NodeInput(mapOf("findings" to findings)), "test-chat"),
        )
        val text = payload.path("text").asText()
        assertEquals("HTML", payload.path("parse_mode").asText())
        assertTrue(text.contains("Repair &lt;Desk&gt; · Проверка завершена"))
        assertTrue(text.contains("<b>Находок: 4</b>"))
        assertTrue(text.contains("Критические — 1 · Высокие — 1 · Средние — 1 · Низкие — 1"))
        assertTrue(text.contains("Секреты — 1 · Зависимости — 1 · Код — 2"))
        assertTrue(text.contains("<code>build&lt;file&gt;.gradle.kts:31</code>"))
        assertTrue(text.contains("Обновите &amp; проверьте ••••"))
        assertTrue(text.indexOf("Critical &lt;risk&gt; &amp; ••••") in 0 until text.indexOf("High priority"))
        assertFalse(text.contains("Low priority"))
        assertFalse(text.contains("raw-token"))
        assertFalse(text.contains("<risk>"))
        assertEquals("Открыть отчёт", payload.at("/reply_markup/inline_keyboard/0/0/text").asText())
        assertEquals("https://demo.example/runs/test/report", payload.at("/reply_markup/inline_keyboard/0/0/url").asText())
    }

    @Test fun `Telegram keeps long values bounded and shows zero only on complete coverage`() {
        val complete = object : NodeContext by context {
            override val coverageStatus = "COMPLETE"
        }
        val empty = NodeInput(emptyMap())
        val completeMessage = output.telegramMessage(complete, empty, "test-chat")
        assertTrue(completeMessage.getValue("text").toString().contains("Находок нет"))
        assertFalse(completeMessage.containsKey("reply_markup"))
        assertFalse(output.telegramMessage(context, empty, "test-chat").getValue("text").toString().contains("Находок нет"))

        val long = "x".repeat(138) + "🐝".repeat(2200)
        val findings = List(3) { index ->
            mapOf("severity" to "HIGH", "title" to long, "path" to "$index/$long", "remediation" to long)
        }
        val text = output.telegramMessage(complete, NodeInput(mapOf("findings" to findings)), "test-chat")
            .getValue("text").toString()
        assertTrue(text.length < 4096 && text.contains("…"))
        assertFalse(text.indices.any { index ->
            text[index].isHighSurrogate() && text.getOrNull(index + 1)?.isLowSurrogate() != true
        })
    }

    @Test fun `partial notifications and Telegram attachment include coverage reasons`() {
        val configured = OutputNodes(json, "", "", "", 587, "", "", "", publicUrl = "https://demo.example/")
        val partial = object : NodeContext by context {
            override val coverageByAnalyzer = mapOf("parse" to json.readTree("""
                {"filesSkipped":[{"path":"src/Broken.kt","line":7,"reason":"Не разобран raw-token"}],
                 "unresolved":[{"path":"build.gradle.kts","line":12,"reason":"Версия неизвестна"},
                   {"path":"A","reason":"a"},{"path":"B","reason":"b"},{"path":"C","reason":"c"},{"path":"D","reason":"d"}]}
            """.trimIndent()))
        }
        val empty = NodeInput(emptyMap())
        val text = configured.notificationText(partial, empty)
        val card = configured.telegramMessage(partial, empty, "test-chat").getValue("text") as String
        val markdown = configured.telegramMarkdown(partial, empty)
        assertTrue(card.contains("Проверка неполная"))
        assertTrue(card.contains("<b>Что осталось непроверенным</b>"))
        assertTrue(card.contains("src/Broken.kt:7 - Не разобран ••••"))
        assertFalse(card.contains("D - d"))
        assertFalse(card.contains("Находок нет"))
        assertTrue(text.contains("src/Broken.kt:7 - Не разобран ••••"))
        assertTrue(text.contains("build.gradle.kts:12 - Версия неизвестна"))
        assertTrue(text.contains("https://demo.example/runs/test"))
        assertTrue(text.contains("C - c"))
        assertFalse(text.contains("D - d"))
        assertFalse(text.contains("Находок: 0"))
        assertFalse(text.contains("raw-token"))
        assertTrue(markdown.contains("src/Broken.kt:7"))
        assertFalse(markdown.contains("raw-token"))
    }

    @Test fun `a stopped check describes an unknown result instead of reporting zero`() {
        val stopped = object : NodeContext by context {
            override val failureReason = "Архив не найден, raw-token"
            override val coverageStatus = "FAILED"
        }
        val text = output.notificationText(stopped, NodeInput(emptyMap()))
        val card = output.telegramMessage(stopped, NodeInput(emptyMap()), "test-chat").getValue("text") as String
        assertTrue(card.contains("Проверка не выполнена"))
        assertTrue(card.contains("Архив не найден, ••••"))
        assertFalse(card.contains("Находок нет"))
        assertTrue(text.contains("Проверка не выполнена, итог неизвестен."))
        assertTrue(text.contains("Архив не найден"))
        assertFalse(text.contains("raw-token"))
        assertFalse(text.contains("Находок: 0"))
    }
}
