package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import workflow.engine.NodeContext

internal val telegramSeverityRanks = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")
    .withIndex().associate { (rank, severity) -> severity to rank }
private val whitespace = Regex("[\\s\\p{Cntrl}]+")

internal data class TelegramCardOptions(
    val english: Boolean = false,
    val topN: Int = 3,
    val onlyNew: Boolean = false,
    val aiSummary: String? = null,
    val index: Int? = null,
) {
    fun word(ru: String, en: String) = if (english) en else ru
}

internal fun telegramPriorityCard(
    ctx: NodeContext,
    findings: List<JsonNode>,
    coverageGaps: Sequence<String>,
    options: TelegramCardOptions,
    redact: (String) -> String,
): String {
    fun text(value: String, limit: Int): String {
        val safe = redact(value).replace(whitespace, " ").trim()
        val escaped = telegramHtml(safe)
        if (escaped.length <= limit) return escaped
        return buildString {
            val points = safe.codePoints().iterator()
            while (points.hasNext()) {
                val part = telegramHtml(String(Character.toChars(points.nextInt())))
                if (length + part.length >= limit) break
                append(part)
            }
            append("…")
        }
    }

    fun StringBuilder.appendAiSummary() {
        options.aiSummary?.let { text(it, 350) }?.takeIf(String::isNotBlank)?.let {
            appendLine()
            appendLine("<b>${options.word("AI-сводка", "AI summary")}</b>")
            appendLine(it)
        }
    }

    val complete = ctx.coverageStatus == "COMPLETE" && ctx.failureReason == null
    val (icon, status) = when {
        ctx.failureReason != null -> "⛔" to options.word("Проверка не выполнена", "Scan failed")
        ctx.coverageStatus == "FAILED" -> "⛔" to options.word("Проверка не завершена", "Scan did not finish")
        complete -> "🛡" to options.word("Проверка завершена", "Scan complete")
        else -> "⚠️" to options.word("Проверка неполная", "Scan incomplete")
    }
    val name = ctx.workflowName?.let { text(it, 100) }?.takeIf(String::isNotBlank)
    return buildString {
        appendLine("$icon <b>${listOfNotNull(name, status).joinToString(" · ")}</b>")
        ctx.failureReason?.let {
            appendLine()
            appendLine(text(it, 320))
        }
        val gaps = coverageGaps.toList()
        if (gaps.isNotEmpty()) {
            appendLine()
            appendLine("<b>${options.word("Что осталось непроверенным", "What could not be checked")}</b>")
            gaps.forEach { appendLine("• ${text(it, 155)}") }
        } else if (!complete && ctx.failureReason == null) {
            appendLine()
            appendLine(options.word("Проверены не все данные.", "Some data could not be checked."))
        }

        if (ctx.failureReason != null) return@buildString
        options.index?.let { index ->
            appendLine()
            val label = if (complete) options.word("Индекс безопасности", "Security index")
                else options.word("Предварительный индекс безопасности", "Preliminary security index")
            appendLine("<b>$label: $index/100</b>")
        }
        if (findings.isEmpty()) {
            if (complete) {
                appendLine()
                val label = if (options.onlyNew) options.word("Новых находок нет", "No new findings")
                    else options.word("Находок нет", "No findings")
                appendLine("<b>$label</b>")
            }
            appendAiSummary()
            return@buildString
        }

        val severityLabels = listOf(
            options.word("Критические", "Critical"), options.word("Высокие", "High"),
            options.word("Средние", "Medium"), options.word("Низкие", "Low"),
        )
        val severityCounts = findings.groupingBy { it.path("severity").asText() }.eachCount()
        val severitySummary = telegramSeverityRanks.mapNotNull { (key, rank) ->
            severityCounts[key]?.let { "${severityLabels[rank]} — $it" }
        }
        val unrated = severityCounts.filterKeys { it !in telegramSeverityRanks }.values.sum()
        appendLine()
        val countLabel = when {
            options.onlyNew -> options.word("Новых находок", "New findings")
            complete -> options.word("Находок", "Findings")
            else -> options.word("Подтверждённых находок", "Confirmed findings")
        }
        appendLine("<b>$countLabel: ${findings.size}</b>")
        val severityItems = if (unrated == 0) severitySummary
            else severitySummary + "${options.word("Без оценки", "Unrated")} — $unrated"
        appendLine(severityItems.joinToString(" · "))

        val priorities = findings.sortedBy { telegramSeverityRanks[it.path("severity").asText()] ?: telegramSeverityRanks.size }
            .take(options.topN)
        appendLine()
        appendLine("<b>${options.word("Что исправить первым", "Fix these first")}</b>")
        for (finding in priorities) {
            val marker = if (finding.path("severity").asText() == "CRITICAL") "🔴" else "•"
            val title = finding.path("title").textValue()?.let { text(it, 95) }
                ?.takeIf(String::isNotBlank) ?: options.word("Находка", "Finding")
            appendLine("$marker <b>$title</b>")
            finding.path("path").textValue()?.takeIf(String::isNotBlank)?.let { path ->
                val line = finding.path("line").asInt().takeIf { it > 0 }
                val location = text(path, 80) + (line?.let { ":$it" } ?: "")
                appendLine("<code>$location</code>")
            }
        }
        priorities.first().path("remediation").textValue()?.let { text(it, 220) }
            ?.takeIf(String::isNotBlank)?.let {
                appendLine()
                appendLine("<b>${options.word("Первый шаг", "First step")}</b>")
                appendLine(it)
            }
        val categoryLabels = linkedMapOf(
            "SECRET" to options.word("Секреты", "Secrets"),
            "SCA" to options.word("Зависимости", "Dependencies"),
            "SAST" to options.word("Код", "Code"),
        )
        val categories = findings.groupingBy { it.path("category").asText() }.eachCount()
        val categorySummary = categoryLabels.mapNotNull { (key, label) ->
            categories[key]?.let { "$label — $it" }
        }
        if (categorySummary.isNotEmpty()) {
            appendLine()
            appendLine(categorySummary.joinToString(" · "))
        }
        appendAiSummary()
    }.trimEnd()
}

/** Карточка итогов запуска для команд бота: тот же формат, что у уведомления `notify.telegram`. */
fun telegramRunCard(
    runId: String,
    workflowName: String?,
    coverageStatus: String,
    failureReason: String?,
    findings: List<JsonNode>,
    topN: Int,
    index: Int?,
    aiSummary: String?,
    redact: (String) -> String,
): String {
    val empty: JsonNode = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode()
    val context = object : NodeContext {
        override val runId = runId
        override val workflowName = workflowName
        override val nodeId = "telegram-bot"
        override val params = empty
        override val workspace: java.nio.file.Path? = null
        override val trigger = empty
        override val coverageStatus = coverageStatus
        override val failureReason = failureReason
        override fun redact(message: String) = message
        override fun log(message: String) = Unit
        override fun emitProgress(percent: Int, note: String?) = Unit
    }
    return telegramPriorityCard(context, findings, emptySequence(),
        TelegramCardOptions(topN = topN, aiSummary = aiSummary, index = index), redact)
}

/** Публичный адрес приложения для кнопок: только http(s)-origin без пути, как в уведомлениях. */
fun telegramPublicOrigin(publicUrl: String): String? = runCatching { java.net.URI(publicUrl.trim()) }.getOrNull()?.takeIf {
    it.scheme in setOf("https", "http") && it.host != null && it.userInfo == null &&
        it.rawPath in setOf("", "/") && it.rawQuery == null && it.rawFragment == null &&
        (it.port == -1 || it.port in 1..65535)
}?.toASCIIString()?.trimEnd('/')
