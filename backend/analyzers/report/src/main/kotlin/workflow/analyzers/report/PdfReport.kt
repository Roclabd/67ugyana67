package workflow.analyzers.report

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.JsonNode
import org.apache.pdfbox.cos.COSArray
import org.apache.pdfbox.cos.COSString
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.font.PDFont
import org.apache.pdfbox.pdmodel.font.PDType0Font
import workflow.engine.securityIndex
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.GregorianCalendar
import java.util.TimeZone

/**
 * PDF-отчёт: рисуется напрямую через PDFBox, шрифт DejaVu Sans (Cyrillic) встраивается из ресурсов.
 * Детерминирован: время берётся только из `meta.finishedAt`, идентификатор документа — хэш запуска.
 * Значения секретов в PDF не попадают: для SECRET используются только сгенерированные тексты и `secretMasked`.
 */
internal class PdfReport(private val report: JsonNode, private val meta: JsonNode?) {
    fun render(): ByteArray = PDDocument().use { doc ->
        val regular = font(doc, "/fonts/DejaVuSans.ttf")
        val bold = font(doc, "/fonts/DejaVuSans-Bold.ttf")
        val w = Writer(doc, regular, bold)
        val runId = report.path("runId").asText("")
        compose(w)
        w.finish(runId.take(8).ifEmpty { "—" })
        val info = doc.documentInformation
        info.title = "$PRODUCT_NAME — отчёт ${runId.take(8)}"
        info.producer = PRODUCT_NAME
        info.creator = PRODUCT_NAME
        val created = meta?.path("finishedAt")?.asText("")?.let { runCatching { Instant.parse(it) }.getOrNull() } ?: Instant.EPOCH
        info.creationDate = GregorianCalendar(TimeZone.getTimeZone("UTC")).apply { timeInMillis = created.toEpochMilli() }
        info.modificationDate = info.creationDate
        val id = COSString(MessageDigest.getInstance("MD5").digest((runId + report.path("rulesVersion").asText()).toByteArray()))
        doc.document.setDocumentID(COSArray().apply { add(id); add(id) })
        ByteArrayOutputStream().also { doc.save(it) }.toByteArray()
    }

    private fun font(doc: PDDocument, resource: String): PDFont =
        requireNotNull(PdfReport::class.java.getResourceAsStream(resource)) { "Нет шрифта $resource" }
            .use { PDType0Font.load(doc, it, true) }

    private fun compose(w: Writer) {
        val findings = sortedFindings()
        val coverage = report.path("coverage")
        val status = coverage.path("status").asText("PARTIAL").takeIf { it in setOf("COMPLETE", "PARTIAL", "FAILED") } ?: "PARTIAL"

        // Титульный блок.
        w.band(
            PRODUCT_NAME.uppercase(), "Отчёт по безопасности кода",
            meta.text("workflowName") ?: report.text("workflowId") ?: "",
        )
        w.gap(16f)
        val runId = report.text("runId") ?: "—"
        val rows = mutableListOf("Запуск" to runId)
        meta.text("workflowName")?.let { rows.add(0, "Процесс" to it) }
        formatDate(meta.text("finishedAt"))?.let { rows.add("Дата и время" to it) }
        meta.text("source")?.let { rows.add("Источник" to it) }
        meta.text("commit")?.let { rows.add("Коммит" to it) }
            ?: report.text("inputHash")?.let { rows.add("Хэш входных данных" to it) }
        report.text("rulesVersion")?.let { rows.add("Версия правил" to it) }
        rows.add("Покрытие анализа" to status)
        w.keyValues(rows)

        w.gap(10f)
        w.coverageBox(status, reasons(coverage, status))
        languagesBlock(w)

        // Сводка.
        w.gap(14f)
        w.h1("Сводка")
        val counts = severities.associateWith { s -> findings.count { it.path("severity").asText() == s } }
        w.severityTable(counts)
        w.gap(8f)
        w.indexLine(securityIndex(counts), status != "COMPLETE", findings.size)

        // Находки.
        w.gap(14f)
        w.h1("Находки по приоритету")
        if (findings.isEmpty()) {
            w.paragraph(
                if (status == "COMPLETE") "Находок нет." else "Находки не зарегистрированы. Итог проверки неизвестен.",
                size = 10f, color = MUTED,
            )
        }
        findings.forEachIndexed { index2, f -> w.finding(index2 + 1, f) }

        // AI.
        aiSection(w, findings)

        // Что проверяли.
        w.gap(14f)
        w.h1("Что проверяли")
        rulesSection(w, coverage)
    }

    /** «Языки проекта»: те же данные, что в JSON и Markdown (`languages`); нет данных — блока нет. */
    private fun languagesBlock(w: Writer) {
        val rows = report.path("languages").takeIf { it.isArray }?.mapNotNull { l ->
            val name = l.text("name") ?: return@mapNotNull null
            val files = l.path("files").takeIf { it.isIntegralNumber && it.asInt() >= 0 }?.asInt() ?: return@mapNotNull null
            val script = l.text("note")?.contains("скрипт") == true
            fun flag(key: String, default: Boolean) =
                if (l.path(key).asBoolean(default)) "да" else if (script) "не применимо" else "не поддерживается"
            listOf(name, files.toString(), flag("secret", true), flag("sast", false), flag("sca", false))
        }.orEmpty()
        if (rows.isEmpty()) return
        w.gap(14f)
        w.h1("Языки проекта")
        w.table(listOf("Язык", "Файлов", "SECRET", "SAST", "SCA"), rows)
    }

    private fun sortedFindings(): List<JsonNode> {
        val list = report.path("findings").takeIf { it.isArray }?.toList().orEmpty().filter { it.isObject }
        return list.sortedWith(compareBy<JsonNode>(
            { severities.indexOf(it.path("severity").asText()).let { i -> if (i < 0) severities.size else i } },
            { it.path("path").asText() }, { it.path("line").asInt() }, { it.path("class").asText(it.path("advisoryId").asText()) },
        ))
    }

    private fun reasons(coverage: JsonNode, status: String): List<String> {
        if (status == "COMPLETE") return emptyList()
        val out = mutableListOf<String>()
        val analyzers = coverage.path("byAnalyzer").fields().asSequence().sortedBy { it.key }.toList()
        for ((name, a) in analyzers) {
            val st = a.path("status").asText("PARTIAL")
            if (st == "COMPLETE") continue
            var any = false
            for (s in a.path("filesSkipped")) {
                out.add("${location(s)} — ${s.text("reason") ?: "причина не указана"}"); any = true
            }
            for (u in a.path("unresolved")) {
                val label = listOfNotNull(u.text("kind"), u.text("subject")).joinToString(" · ")
                out.add("${location(u)}${if (label.isEmpty()) "" else " · $label"} — ${u.text("reason") ?: "причина не указана"}"); any = true
            }
            if (!any) out.add("Анализатор $name: $st, причина не указана.")
        }
        return out
    }

    private fun aiSection(w: Writer, findings: List<JsonNode>) {
        val ai = report.path("ai")
        val status = ai.text("status") ?: "NOT_RECEIVED"
        w.gap(14f)
        w.h1("AI-анализ")
        if (status == "NOT_RECEIVED" || !ai.isObject) {
            w.paragraph("AI-объяснение не получено. Отчёт построен только по результатам анализаторов.", size = 10f, color = MUTED)
            return
        }
        ai.text("model")?.let { w.paragraph("Модель: $it · статус: $status", size = 9f, color = MUTED) }
        ai.text("summary")?.let { w.gap(4f); w.paragraph(it, size = 10f) }
        val byId = findings.associateBy { it.text("id") ?: it.text("fingerprint") ?: "" }
        val order = ai.path("priorities").mapNotNull { id -> byId[id.asText()] }
        if (order.isNotEmpty()) {
            w.gap(8f)
            w.paragraph("Порядок исправления", bold = true, size = 10.5f)
            order.forEachIndexed { i, f ->
                w.paragraph("${i + 1}. [${f.path("severity").asText()}] ${titleOf(f)} — ${location(f)}", size = 9.5f, indent = 10f)
            }
        }
        for (g in ai.path("groups")) {
            val title = g.text("title") ?: continue
            w.gap(6f)
            w.paragraph(title, bold = true, size = 10f)
            g.text("story")?.let { w.paragraph(it, size = 9.5f, color = MUTED) }
        }
    }

    private fun rulesSection(w: Writer, coverage: JsonNode) {
        val analyzers = coverage.path("byAnalyzer").fields().asSequence().sortedBy { it.key }.toList()
        if (analyzers.isEmpty()) {
            w.paragraph("Сведения о применённых правилах отсутствуют.", size = 10f, color = MUTED)
            return
        }
        for ((name, a) in analyzers) {
            val files = a.path("filesAnalyzed").takeIf { it.isIntegralNumber }?.asInt()?.toString() ?: "неизвестно"
            w.paragraph("$name · ${a.path("status").asText("PARTIAL")} · разобрано файлов: $files", bold = true, size = 10f)
            val rules = a.path("rulesApplied").takeIf { it.isArray } ?: a.path("rules")
            val lines = rules.mapNotNull { r ->
                if (r.isTextual) r.asText().takeIf { it.isNotBlank() }
                else listOfNotNull(r.text("title"), r.text("id")?.let { "($it)" }).joinToString(" ")
                    .plus(r.text("description")?.let { " — $it" }.orEmpty()).takeIf { it.isNotBlank() }
            }.distinct()
            if (lines.isEmpty()) w.paragraph("Правила не перечислены.", size = 9f, color = MUTED, indent = 10f)
            lines.forEach { w.paragraph("• $it", size = 9f, indent = 10f) }
            w.gap(4f)
        }
    }

    private fun titleOf(f: JsonNode): String {
        val cls = f.text("class")
        return when (f.text("category")) {
            "SECRET" -> classNames[cls] ?: "Встроенный секрет"
            "SCA" -> "Уязвимая зависимость ${listOfNotNull(f.text("artifact"), f.text("version")).joinToString(" ")}".trim()
            else -> f.text("title") ?: classNames[cls] ?: cls ?: "Находка"
        }
    }

    private fun projectRelative(value: String): String? {
        val p = value.replace('\\', '/')
        if (p.startsWith("/") || ":" in p) return null
        val parts = p.split("/")
        if (".." in parts) return null
        return parts.filter { it.isNotEmpty() && it != "." }.joinToString("/").takeIf(String::isNotBlank)
    }

    private fun location(f: JsonNode): String {
        val path = f.text("path")?.let { projectRelative(it) ?: "— (путь вне проекта скрыт)" } ?: "—"
        val line = f.path("line").takeIf { it.isIntegralNumber && it.asInt() > 0 }?.asInt() ?: return path
        val end = f.path("endLine").takeIf { it.isIntegralNumber && it.asInt() > line }?.asInt()
        return if (end != null) "$path:$line–$end" else "$path:$line"
    }

    private fun Writer.finding(n: Int, f: JsonNode) {
        val severity = f.text("severity") ?: "INFO"
        val category = f.text("category") ?: ""
        val secret = category == "SECRET"
        ensure(70f)
        gap(6f)
        chip(severity, SEVERITY_COLORS[severity] ?: MUTED)
        paragraph("$n. ${titleOf(f)}", bold = true, size = 11f, x = MARGIN + 74f)
        val cls = f.text("class")
        val kind = buildString {
            append(category.ifEmpty { "—" })
            cls?.let { append(" · ").append(classNames[it] ?: it) }
        }
        paragraph("$kind · ${location(f)}", size = 9f, color = MUTED)
        if (category == "SCA") {
            val dep = listOfNotNull(f.text("group"), f.text("artifact"), f.text("version")).joinToString(":")
            paragraph("Зависимость: $dep · ${f.text("advisoryId") ?: ""}", size = 9.5f)
            val fixed = f.path("fixedVersions").mapNotNull { it.textValue() }
            if (fixed.isNotEmpty()) paragraph("Исправлено в версиях: ${fixed.joinToString(", ")}", size = 9.5f)
        }
        if (secret) {
            paragraph("Значение: ${f.text("secretMasked") ?: "****"} (маскировано)", size = 9.5f)
            paragraph("Секрет обнаружен в исходном коде. Значение в отчёт не включается.", size = 9.5f)
            paragraph("Рекомендация: $SECRET_REMEDIATION", size = 9.5f)
        } else {
            f.text("description")?.let { paragraph(it, size = 9.5f) }
            f.text("remediation")?.let { paragraph("Рекомендация: $it", size = 9.5f) }
            f.path("ai").takeIf { it.path("status").asText() == "OK" }?.let { ai ->
                ai.text("impact")?.let { paragraph("Влияние: $it", size = 9.5f, color = MUTED) }
            }
            val evidence = f.path("evidence").filter { it.isObject }
            if (evidence.isNotEmpty()) {
                paragraph("Цепочка доказательств:", bold = true, size = 9f)
                evidence.take(12).forEachIndexed { i, e ->
                    paragraph("${i + 1}) ${location(e)}${e.text("note")?.let { " — $it" }.orEmpty()}", size = 9f, indent = 10f, color = MUTED)
                }
                if (evidence.size > 12) paragraph("… и ещё ${evidence.size - 12}", size = 9f, indent = 10f, color = MUTED)
            }
        }
        // Для секретов цепочка — только места, без сопроводительных заметок.
        if (secret) {
            val evidence = f.path("evidence").filter { it.isObject }
            if (evidence.size > 1) {
                paragraph("Места:", bold = true, size = 9f)
                evidence.take(12).forEach { paragraph(location(it), size = 9f, indent = 10f, color = MUTED) }
            }
        }
        gap(4f)
        separator()
    }

    private fun formatDate(value: String?): String? = value?.let {
        runCatching { DATE.format(Instant.parse(it)) }.getOrDefault(it)
    }

    private fun JsonNode?.text(name: String): String? = this?.path(name)?.takeIf { it.isValueNode && !it.isNull }?.asText()?.takeIf { it.isNotBlank() }

    private companion object {
        const val MARGIN = 48f
        val DATE: DateTimeFormatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm 'UTC'").withZone(ZoneOffset.UTC)
        val severities = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")
        const val SECRET_REMEDIATION = "Перенесите значение в переменную окружения или хранилище секретов. Если значение использовалось, замените его."
        val classNames = mapOf(
            "sql-injection" to "SQL-инъекция",
            "route-authorization" to "Маршрут без проверки доступа",
            "object-authorization" to "Нет проверки прав на объект (IDOR)",
            "tls-verification" to "Отключена проверка TLS",
            "credentialed-cors" to "Небезопасный CORS с учётными данными",
            "password" to "Пароль в исходниках",
            "api-key" to "Ключ API в исходниках",
            "configuration-token" to "Секрет в конфигурации",
            "secret-fallback" to "Секрет в значении по умолчанию",
            "recoverable-token" to "Секрет восстанавливается из констант",
            "high-entropy" to "Строка похожа на ключ (высокая энтропия)",
            "custom-regex" to "Совпадение с пользовательским правилом",
        )
        val SEVERITY_COLORS = mapOf(
            "CRITICAL" to floatArrayOf(0.70f, 0.10f, 0.15f), "HIGH" to floatArrayOf(0.85f, 0.35f, 0.10f),
            "MEDIUM" to floatArrayOf(0.80f, 0.58f, 0.02f), "LOW" to floatArrayOf(0.20f, 0.42f, 0.72f),
            "INFO" to floatArrayOf(0.45f, 0.48f, 0.52f),
        )
        val MUTED = floatArrayOf(0.38f, 0.42f, 0.47f)
        val INK = floatArrayOf(0.09f, 0.11f, 0.15f)
        val NAVY = floatArrayOf(0.05f, 0.13f, 0.24f)
        val STATUS_COLORS = mapOf(
            "COMPLETE" to floatArrayOf(0.10f, 0.50f, 0.30f), "PARTIAL" to floatArrayOf(0.80f, 0.50f, 0.02f),
            "FAILED" to floatArrayOf(0.70f, 0.10f, 0.15f),
        )
        val STATUS_TEXT = mapOf(
            "COMPLETE" to ("Покрытие полное" to "Все файлы проекта разобраны. Отсутствие находок означает, что применённые правила проблем не нашли."),
            "PARTIAL" to ("PARTIAL — проверка неполная" to "Часть проекта не проверена. Итог неизвестен: отсутствие находок не означает безопасность. Причины ниже."),
            "FAILED" to ("FAILED — анализ завершился ошибкой" to "Проверка не выполнена полностью. Итог неизвестен, результаты нельзя считать подтверждением безопасности. Причины ниже."),
        )
    }

    /** Низкоуровневая вёрстка: перенос строк, страницы, колонтитулы. */
    private class Writer(val doc: PDDocument, val regular: PDFont, val bold: PDFont) {
        val pageW = PDRectangle.A4.width
        val pageH = PDRectangle.A4.height
        val contentW = pageW - 2 * MARGIN
        val bottom = MARGIN + 28f
        val pages = mutableListOf<PDPage>()
        lateinit var stream: PDPageContentStream
        var y = 0f

        init { newPage() }

        fun newPage() {
            if (pages.isNotEmpty()) stream.close()
            val page = PDPage(PDRectangle.A4)
            doc.addPage(page)
            pages.add(page)
            stream = PDPageContentStream(doc, page)
            y = pageH - MARGIN
        }

        fun ensure(height: Float) { if (y - height < bottom) newPage() }
        fun gap(h: Float) { y -= h; if (y < bottom) newPage() }

        fun safe(font: PDFont, text: String): String {
            val sb = StringBuilder()
            text.codePoints().forEach { cp ->
                val c = when {
                    cp == '\t'.code -> ' '.code
                    cp < 32 || cp == 0x7f || cp in 0x2028..0x2029 -> ' '.code
                    else -> cp
                }
                sb.appendCodePoint(if (runCatching { font.encode(String(Character.toChars(c))) }.isSuccess) c else 63)
            }
            return sb.toString()
        }

        fun width(font: PDFont, size: Float, s: String) = font.getStringWidth(s) / 1000f * size

        fun wrap(text: String, font: PDFont, size: Float, maxW: Float): List<String> {
            val out = mutableListOf<String>()
            for (para in text.split('\n')) {
                var line = ""
                for (word in safe(font, para).split(' ').filter { it.isNotEmpty() }) {
                    var token = word
                    while (width(font, size, token) > maxW) { // длинный путь или хэш: режем по символам
                        if (line.isNotEmpty()) { out.add(line); line = "" }
                        var cut = token.length
                        while (cut > 1 && width(font, size, token.substring(0, cut)) > maxW) cut--
                        out.add(token.substring(0, cut)); token = token.substring(cut)
                    }
                    val candidate = if (line.isEmpty()) token else "$line $token"
                    if (width(font, size, candidate) <= maxW) line = candidate
                    else { out.add(line); line = token }
                }
                out.add(line)
            }
            return out
        }

        fun drawLine(s: String, font: PDFont, size: Float, color: FloatArray, x: Float) {
            stream.beginText()
            stream.setFont(font, size)
            stream.setNonStrokingColor(color[0], color[1], color[2])
            stream.newLineAtOffset(x, y)
            stream.showText(s)
            stream.endText()
        }

        fun paragraph(
            text: String, size: Float = 10f, bold: Boolean = false, color: FloatArray = INK,
            indent: Float = 0f, x: Float = MARGIN,
        ) {
            val font = if (bold) this.bold else regular
            val left = x + indent
            val lead = size * 1.38f
            for (line in wrap(text, font, size, MARGIN + contentW - left)) {
                if (y - lead < bottom) newPage()
                y -= lead
                if (line.isNotEmpty()) drawLine(line, font, size, color, left)
            }
        }

        fun h1(text: String) {
            ensure(60f)
            y -= 16f
            drawLine(safe(bold, text), bold, 15f, NAVY, MARGIN)
            y -= 5f
            stream.setStrokingColor(0.80f, 0.83f, 0.87f)
            stream.setLineWidth(0.8f)
            stream.moveTo(MARGIN, y); stream.lineTo(MARGIN + contentW, y); stream.stroke()
            y -= 4f
        }

        fun separator() {
            stream.setStrokingColor(0.88f, 0.90f, 0.93f)
            stream.setLineWidth(0.6f)
            stream.moveTo(MARGIN, y); stream.lineTo(MARGIN + contentW, y); stream.stroke()
        }

        fun rect(x: Float, yy: Float, w: Float, h: Float, c: FloatArray) {
            stream.setNonStrokingColor(c[0], c[1], c[2])
            stream.addRect(x, yy, w, h); stream.fill()
        }

        /** Плашка критичности слева от заголовка находки; y остаётся на уровне плашки. */
        fun chip(label: String, color: FloatArray) {
            val h = 15f
            y -= h
            rect(MARGIN, y - 3f, 66f, h, color)
            val tw = width(bold, 8f, label)
            stream.beginText(); stream.setFont(bold, 8f); stream.setNonStrokingColor(1f, 1f, 1f)
            stream.newLineAtOffset(MARGIN + (66f - tw) / 2, y + 1.5f); stream.showText(safe(bold, label)); stream.endText()
            y += h
        }

        fun band(kicker: String, title: String, subtitle: String) {
            val h = 118f
            rect(0f, pageH - h, pageW, h, NAVY)
            rect(0f, pageH - h, pageW, 4f, STATUS_COLORS.getValue("COMPLETE"))
            y = pageH - 38f
            drawLine(kicker, bold, 10f, floatArrayOf(0.55f, 0.85f, 0.70f), MARGIN)
            y -= 32f
            drawLine(safe(bold, title), bold, 24f, floatArrayOf(1f, 1f, 1f), MARGIN)
            if (subtitle.isNotBlank()) {
                y -= 22f
                val s = wrap(subtitle, regular, 11f, contentW).first()
                drawLine(s, regular, 11f, floatArrayOf(0.80f, 0.85f, 0.92f), MARGIN)
            }
            y = pageH - h
        }

        fun keyValues(rows: List<Pair<String, String>>) {
            val labelW = 130f
            for ((k, v) in rows) {
                val lines = wrap(v, regular, 10f, contentW - labelW)
                ensure(lines.size * 14f + 4f)
                val top = y
                y -= 14f
                drawLine(safe(regular, k), regular, 9.5f, MUTED, MARGIN)
                var first = true
                for (l in lines) {
                    if (!first) y -= 13.5f
                    first = false
                    drawLine(l, if (k == "Покрытие анализа") bold else regular, 10f, INK, MARGIN + labelW)
                }
                y -= 4f
                stream.setStrokingColor(0.91f, 0.93f, 0.95f); stream.setLineWidth(0.5f)
                stream.moveTo(MARGIN, y); stream.lineTo(MARGIN + contentW, y); stream.stroke()
                check(top >= y)
            }
        }

        fun coverageBox(status: String, reasons: List<String>) {
            val (head, body) = STATUS_TEXT.getValue(status)
            val color = STATUS_COLORS.getValue(status)
            val bodyLines = wrap(body, regular, 9.5f, contentW - 24f)
            ensure(34f + bodyLines.size * 13f)
            val h = 22f
            y -= h
            rect(MARGIN, y, contentW, h, color)
            y += 7f
            drawLine(safe(bold, head), bold, 11f, floatArrayOf(1f, 1f, 1f), MARGIN + 10f)
            y -= 7f
            y -= 3f
            paragraph(body, size = 9.5f, indent = 10f)
            if (reasons.isNotEmpty()) {
                gap(4f)
                paragraph("Причины (файл:строка — причина):", bold = true, size = 9.5f, indent = 10f)
                reasons.take(30).forEach { paragraph("• $it", size = 9f, indent = 18f, color = MUTED) }
                if (reasons.size > 30) paragraph("… и ещё ${reasons.size - 30}. Полный список — в report.json.", size = 9f, indent = 18f, color = MUTED)
            }
        }

        fun table(header: List<String>, rows: List<List<String>>) {
            val widths = listOf(0.20f, 0.11f, 0.13f, 0.28f, 0.28f).map { it * contentW }
            fun row(cells: List<String>, font: PDFont, color: FloatArray) {
                ensure(20f)
                y -= 16f
                var x = MARGIN
                cells.forEachIndexed { i, c ->
                    drawLine(wrap(c, font, 9.5f, widths[i] - 6f).first(), font, 9.5f, color, x)
                    x += widths[i]
                }
                y -= 4f
                stream.setStrokingColor(0.91f, 0.93f, 0.95f); stream.setLineWidth(0.5f)
                stream.moveTo(MARGIN, y); stream.lineTo(MARGIN + contentW, y); stream.stroke()
            }
            gap(2f)
            row(header, bold, MUTED)
            rows.forEach { row(it, regular, INK) }
        }

        fun severityTable(counts: Map<String, Int>) {
            val max = (counts.values.maxOrNull() ?: 0).coerceAtLeast(1)
            ensure(counts.size * 20f + 24f)
            gap(4f)
            for ((s, n) in counts) {
                y -= 18f
                val color = SEVERITY_COLORS.getValue(s)
                drawLine(s, bold, 9.5f, color, MARGIN)
                drawLine(n.toString(), bold, 10f, INK, MARGIN + 80f)
                rect(MARGIN + 115f, y - 1f, contentW - 115f, 9f, floatArrayOf(0.93f, 0.94f, 0.96f))
                if (n > 0) rect(MARGIN + 115f, y - 1f, (contentW - 115f) * n / max, 9f, color)
            }
            y -= 20f
            drawLine("Всего: ${counts.values.sum()}", regular, 9.5f, MUTED, MARGIN)
        }

        fun indexLine(index: Int, partial: Boolean, total: Int) {
            ensure(46f)
            y -= 26f
            val c = when { index >= 80 -> STATUS_COLORS.getValue("COMPLETE"); index >= 50 -> STATUS_COLORS.getValue("PARTIAL"); else -> STATUS_COLORS.getValue("FAILED") }
            drawLine("Индекс безопасности: $index / 100", bold, 14f, c, MARGIN)
            y -= 4f
            paragraph(
                "Формула: 100 − 8·критических − 2·высоких − средние − округление вверх (низкие/2), не меньше 0." +
                    if (partial) " Покрытие неполное, индекс считается только по найденному и не гарантирует безопасность." else "",
                size = 8.5f, color = MUTED,
            )
        }

        fun finish(shortId: String) {
            stream.close()
            pages.forEachIndexed { i, page ->
                PDPageContentStream(doc, page, PDPageContentStream.AppendMode.APPEND, true, true).use { s ->
                    s.setStrokingColor(0.80f, 0.83f, 0.87f); s.setLineWidth(0.6f)
                    s.moveTo(MARGIN, MARGIN + 6f); s.lineTo(MARGIN + contentW, MARGIN + 6f); s.stroke()
                    val left = "$PRODUCT_NAME · отчёт $shortId"
                    val right = "Страница ${i + 1} из ${pages.size}"
                    s.beginText(); s.setFont(regular, 8f); s.setNonStrokingColor(MUTED[0], MUTED[1], MUTED[2])
                    s.newLineAtOffset(MARGIN, MARGIN - 6f); s.showText(safe(regular, left)); s.endText()
                    s.beginText(); s.setFont(regular, 8f); s.setNonStrokingColor(MUTED[0], MUTED[1], MUTED[2])
                    s.newLineAtOffset(MARGIN + contentW - width(regular, 8f, right), MARGIN - 6f); s.showText(safe(regular, right)); s.endText()
                }
            }
        }
    }
}
