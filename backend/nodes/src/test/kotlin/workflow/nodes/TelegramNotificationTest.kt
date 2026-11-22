package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import workflow.engine.*
import java.io.ByteArrayOutputStream
import java.nio.file.Path
import java.util.Collections

class TelegramNotificationTest {
    private val json = ObjectMapper()
    private val token = "123456:telegram-fixture-token"
    private val history = TelegramRunHistory { _, findings ->
        TelegramPreviousRun("previous-run", findings.orEmpty().filterNot { it.path("path").asText() == "Old.kt" })
    }

    private class RecordingTransport(private val json: ObjectMapper) : TelegramTransport {
        val messages = Collections.synchronizedList(mutableListOf<JsonNode>())
        val documents = Collections.synchronizedList(mutableListOf<Pair<TelegramDestination, TelegramAttachment>>())

        override fun message(token: String, body: String) {
            messages.add(json.readTree(body))
        }

        override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) {
            documents += destination to attachment
        }
    }

    private val exporter = object : ReportExporter {
        override fun json(report: JsonNode) = report
        override fun markdown(report: JsonNode) = report.path("findings").joinToString("\n") { it.path("title").asText() }
        override fun sarif(report: JsonNode) = json.createObjectNode().put("version", "2.1.0").set<JsonNode>("runs", report)
        override fun pdf(report: JsonNode, meta: JsonNode?) =
            ("%PDF-1.7\n" + report + "\n" + meta).toByteArray()
    }

    private fun output(
        transport: RecordingTransport,
        url: String = "",
        defaults: List<TelegramFormat> = listOf(TelegramFormat.PDF),
        history: TelegramRunHistory = this.history,
        exporter: ReportExporter = this.exporter,
    ) = OutputNodes(
        json, "", "", "", 587, "", "", "", exporter, url,
        TelegramDefaultsSource { TelegramDefaults(token, "42", defaults) }, history, transport,
    )

    private fun params() = json.createObjectNode()

    private fun context(params: ObjectNode, logs: MutableList<String> = mutableListOf()) = object : NodeContext {
        override val runId = "current-run"
        override val workflowName = "Workflow $token"
        override val nodeId = "send"
        override val params = params
        override val workspace: Path? = null
        override val trigger = json.createObjectNode()
        override val coverageStatus = "COMPLETE"
        override fun redact(message: String) = message.replace("raw-secret-value", Redaction.MASK)
        override fun log(message: String) { logs += message }
        override fun emitProgress(percent: Int, note: String?) = Unit
    }

    private fun finding(path: String, severity: String = "HIGH", title: String = path): JsonNode =
        json.createObjectNode().put("path", path).put("severity", severity).put("category", "SAST")
            .put("line", 7).put("title", title)

    private fun send(out: OutputNodes, ctx: NodeContext, vararg findings: JsonNode): NodeOutput =
        runBlocking { out.telegram().run(ctx, NodeInput(mapOf("findings" to findings.toList()))) }

    @Test fun allFormatsSendMaskedFilesAndNodeOverridesGlobalDefault() {
        for (format in TelegramFormat.entries) {
            val transport = RecordingTransport(json)
            val out = output(transport)
            val ctx = context(params().put("format", format.value))
            send(out, ctx, finding("Example.kt", title = "<example> $token raw-secret-value"))
            val card = transport.messages.single().path("text").asText()
            assertFalse(card.contains(token))
            assertFalse(card.contains("raw-secret-value"))
            if (format == TelegramFormat.NONE) {
                assertTrue(transport.documents.isEmpty())
                continue
            }
            val attachment = transport.documents.single().second
            assertTrue(attachment.filename.endsWith(".${format.value}"))
            assertEquals(format.contentType, attachment.contentType)
            val text = attachment.content.toString(Charsets.UTF_8)
            assertFalse(text.contains(token))
            assertFalse(text.contains("raw-secret-value"))
            assertTrue(text.contains(Redaction.MASK))
            if (format == TelegramFormat.HTML) assertTrue(text.contains("&lt;example&gt;"))
            if (format == TelegramFormat.JSON) assertEquals(1, json.readTree(text).path("findings").size())
            if (format == TelegramFormat.SARIF) assertEquals("2.1.0", json.readTree(text).path("version").asText())
        }

        val transport = RecordingTransport(json)
        send(output(transport, defaults = listOf(TelegramFormat.JSON)), context(params()), finding("Default.kt"))
        assertEquals("report.json", transport.documents.single().second.filename)
    }

    private fun names(t: RecordingTransport) = t.documents.map { it.second.filename.substringAfterLast('.') }

    @Test fun attachmentsParsingNewLegacyNoneAndInvalid() {
        fun parse(p: ObjectNode) = TelegramFormat.fromParams(p)
        fun arr(vararg v: String): ObjectNode = json.createObjectNode().apply { putArray("attachments").also { a -> v.forEach(a::add) } }
        assertEquals(listOf(TelegramFormat.PDF, TelegramFormat.MARKDOWN), parse(arr("md", "pdf")))
        assertEquals(listOf(TelegramFormat.MARKDOWN), parse(arr("md", "md")))
        assertEquals(emptyList<TelegramFormat>(), parse(arr()))
        assertEquals(listOf(TelegramFormat.HTML), parse(params().put("format", "html")))
        assertEquals(emptyList<TelegramFormat>(), parse(params().put("format", "none")))
        assertEquals(listOf(TelegramFormat.JSON), parse(arr("json").put("format", "pdf")))
        assertNull(parse(params()))
        assertNull(parse(arr("exe")))
        assertNull(parse(arr("none")))
        val schema = output(RecordingTransport(json)).telegram().paramsSchema.toString()
        assertTrue(schema.contains("uniqueItems"))
    }

    @Test fun severalAttachmentsAreSentInOrderAndMasked() {
        val transport = RecordingTransport(json)
        val ctx = context(params().apply { putArray("attachments").add("sarif").add("md").add("pdf") })
        send(output(transport), ctx, finding("A.kt", title = "$token raw-secret-value"))
        assertEquals(listOf("pdf", "md", "sarif"), names(transport))
        transport.documents.forEach {
            val text = it.second.content.toString(Charsets.UTF_8)
            assertFalse(text.contains(token))
            assertFalse(text.contains("raw-secret-value"))
        }
        val none = RecordingTransport(json)
        send(output(none), context(params().apply { putArray("attachments") }), finding("A.kt"))
        assertTrue(none.documents.isEmpty())
        val legacyDefault = RecordingTransport(json)
        send(output(legacyDefault, defaults = listOf(TelegramFormat.MARKDOWN, TelegramFormat.HTML)), context(params()), finding("A.kt"))
        assertEquals(listOf("md", "html"), names(legacyDefault))
    }

    private val brokenPdf = object : ReportExporter by exporter {
        override fun pdf(report: JsonNode, meta: JsonNode?): ByteArray = error("pdf down")
    }

    @Test fun pdfFailureFallsBackToMarkdownWithoutDuplicate() {
        val only = RecordingTransport(json)
        val status = send(output(only, exporter = brokenPdf),
            context(params().apply { putArray("attachments").add("pdf") }), finding("A.kt")).status
        assertEquals(NodeStatus.SUCCESS, status)
        assertEquals(listOf("md"), names(only))
        val both = RecordingTransport(json)
        send(output(both, exporter = brokenPdf),
            context(params().apply { putArray("attachments").add("pdf").add("md") }), finding("A.kt"))
        assertEquals(listOf("md"), names(both))
    }

    @Test fun partialFileFailureReportsWhichFilesFailed() {
        val transport = object : TelegramTransport {
            val sent = mutableListOf<String>()
            override fun message(token: String, body: String) = Unit
            override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) {
                if (attachment.filename.endsWith(".md")) error("boom")
                sent += attachment.filename
            }
        }
        val out = OutputNodes(json, "", "", "", 587, "", "", "", exporter, "",
            TelegramDefaultsSource { TelegramDefaults(token, "42", listOf(TelegramFormat.PDF)) }, history, transport)
        val ctx = context(params().apply { putArray("attachments").add("pdf").add("md").add("json") })
        val failure = assertThrows(NodeFailure::class.java) { send(out, ctx, finding("A.kt")) }
        assertTrue(failure.message!!.contains("md"))
        assertFalse(failure.message!!.contains("pdf"))
        assertEquals(2, transport.sent.size)
    }

    @Test fun tooManyRequestsIsRetriedAndGivesUp() {
        val flaky = object : TelegramTransport {
            var calls = 0
            val sent = mutableListOf<String>()
            override fun message(token: String, body: String) {
                if (calls++ < 2) throw DeliveryHttpFailure(429, 0)
                sent += body
            }
            override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) = Unit
        }
        val out = OutputNodes(json, "", "", "", 587, "", "", "", exporter, "",
            TelegramDefaultsSource { TelegramDefaults(token, "42", listOf(TelegramFormat.PDF)) }, history, flaky)
        assertEquals(NodeStatus.SUCCESS, send(out, context(params()), finding("A.kt")).status)
        assertEquals(1, flaky.sent.size)
        assertEquals(3, flaky.calls)

        val always = object : TelegramTransport {
            var calls = 0
            override fun message(token: String, body: String) { calls++; throw DeliveryHttpFailure(429, 0) }
            override fun document(token: String, destination: TelegramDestination, attachment: TelegramAttachment) = Unit
        }
        val failing = OutputNodes(json, "", "", "", 587, "", "", "", exporter, "",
            TelegramDefaultsSource { TelegramDefaults(token, "42", listOf(TelegramFormat.PDF)) }, history, always)
        assertThrows(NodeFailure::class.java) { send(failing, context(params()), finding("A.kt")) }
        assertEquals(3, always.calls)

    }

    @Test fun exhaustedRetryBudgetMarksOnlyThatChatFailed() {
        val calls = java.util.concurrent.ConcurrentHashMap<String, Int>()
        val result = runBlocking {
            sendTelegramBatch(listOf("ok", "limited"), java.util.concurrent.atomic.AtomicLong(0)) { chat ->
                calls.merge(chat, 1, Int::plus)
                if (chat == "limited") throw DeliveryHttpFailure(429, 1)
            }
        }
        assertEquals(listOf("ok"), result.sent)
        assertEquals(429, (result.failure as DeliveryHttpFailure).status)
        assertEquals(1, calls["limited"])
    }

    @Test fun chatListLimitIs4096CharactersNotCount() {
        val ids = { n: Int -> (1..n).joinToString(",") { "$it" } }
        assertEquals(500, telegramChats(ids(500))?.size)
        assertNull(telegramChats(",1".repeat(TELEGRAM_CHAT_LIST_MAX_LENGTH)))
        assertNull(telegramChats("1,".repeat(TELEGRAM_CHAT_LIST_MAX_LENGTH) + "2"))
        val many = RecordingTransport(json)
        send(output(many), context(params().put("chatId", ids(30))), finding("A.kt"))
        assertEquals(30, many.messages.size)
    }

    @Test fun sendsCardAndAttachmentToEveryDistinctRecipientInALongList() {
        val transport = RecordingTransport(json)
        val recipients = (1..32).map { "@codeguard_test_chat_$it" }
        val chatList = (recipients + recipients.first()).joinToString(", ")
        val out = output(transport)
        val ctx = context(params().put("chatId", chatList))
        assertEquals(NodeStatus.SUCCESS, send(out, ctx, finding("Example.kt")).status)
        assertEquals(recipients.sorted(), transport.messages.map { it.path("chat_id").asText() }.sorted())
        assertEquals(recipients.sorted(), transport.documents.map { it.first.chatId }.sorted())
        assertNull(telegramChats("1,".repeat(TELEGRAM_CHAT_LIST_MAX_LENGTH) + "2"))
    }

    @Test fun onlyNewAndSeverityGateCardAndDeliveryStatus() {
        val transport = RecordingTransport(json)
        val out = output(transport)
        val logs = mutableListOf<String>()
        val ctx = context(params().put("onlyNew", true).put("minSeverity", "HIGH"), logs)
        val old = finding("Old.kt", "CRITICAL")
        val low = finding("Low.kt", "LOW")
        val high = finding("New.kt", "HIGH")
        assertEquals(NodeStatus.SKIPPED, send(out, ctx, old, low).status)
        assertTrue(logs.single().contains("пропущено по порогу"))
        assertTrue(transport.messages.isEmpty())
        assertEquals(NodeStatus.SUCCESS, send(out, ctx, old, low, high).status)
        val card = transport.messages.single().path("text").asText()
        assertTrue(card.contains("Новых находок: 2"))
        assertTrue(card.contains("New.kt"))
        assertFalse(card.contains("Old.kt"))
        assertFalse(transport.documents.single().second.content.toString(Charsets.UTF_8).contains("Old.kt"))

        val onlyNew = context(params().put("onlyNew", true))
        assertEquals(NodeStatus.SKIPPED, send(out, onlyNew, old).status)
        val first = RecordingTransport(json)
        send(output(first, history = TelegramRunHistory { _, _ -> null }), onlyNew, old)
        assertTrue(first.messages.single().path("text").asText().contains("Old.kt"))
    }

    @Test fun publicAddressAddsUrlButtonsAndRecipientOptionsApplyToBothRequests() {
        val transport = RecordingTransport(json)
        val settings = params().put("chatId", "11, -22, 11").put("threadId", 12).put("silent", true)
            .put("language", "en").put("topN", 10).put("includeIndex", true)
        val findings = List(12) { finding("Finding-$it.kt", title = "x".repeat(1000)) }
        send(output(transport, "https://demo.example/"), context(settings), *findings.toTypedArray())
        assertEquals(listOf("-22", "11"), transport.messages.map { it.path("chat_id").asText() }.sorted())
        val first = transport.messages.single { it.path("chat_id").asText() == "11" }
        assertEquals(12, first.path("message_thread_id").asInt())
        assertTrue(first.path("disable_notification").asBoolean())
        assertTrue(first.path("text").asText().contains("Security index: 76/100"))
        assertTrue(first.path("text").asText().contains("Finding-9.kt"))
        assertFalse(first.path("text").asText().contains("Finding-10.kt"))
        assertTrue(first.path("text").asText().length <= 4096)
        val buttons = first.at("/reply_markup/inline_keyboard").flatMap { row -> row.toList() }
        assertEquals(listOf(
            "https://demo.example/runs/current-run/report",
            "https://demo.example/api/runs/current-run/report.pdf",
            "https://demo.example/compare?base=previous-run&head=current-run",
        ), buttons.map { it.path("url").asText() })
        assertTrue(buttons.none { it.has("callback_data") })
        val (destination, attachment) = transport.documents.single { it.first.chatId == "11" }
        assertEquals(TelegramDestination("11", 12, true), destination)
        val multipart = ByteArrayOutputStream().also(PublicNetwork.telegramDocumentBody(destination, attachment)::writeTo)
            .toString(Charsets.UTF_8)
        assertTrue(multipart.contains("name=\"message_thread_id\""))
        assertTrue(multipart.contains("name=\"disable_notification\""))

        val noUrl = RecordingTransport(json)
        send(output(noUrl), context(params()), finding("A.kt"))
        assertFalse(noUrl.messages.single().has("reply_markup"))
        val badOrigin = RecordingTransport(json)
        send(output(badOrigin, "https://user@demo.example/"), context(params()), finding("A.kt"))
        assertFalse(badOrigin.messages.single().has("reply_markup"))
    }
}
