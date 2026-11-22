package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import workflow.engine.RunStatus
import workflow.nodes.TelegramPreviousRun
import workflow.nodes.TelegramRunHistory
import workflow.nodes.findingsOf
import kotlin.math.abs

/** Сторона сравнения: что именно проверялось. */
data class CompareSide(
    val runId: String,
    val status: RunStatus,
    val coverageStatus: String?,
    val kind: String?,
    val repoUrl: String?,
    val commitSha: String?,
    val inputHash: String?,
    val subdir: String,
    val rulesVersion: String?,
    val workflowId: String,
    val workflowVersion: Long,
    val startedAt: String,
)

data class CompareResult(
    val base: CompareSide,
    val head: CompareSide,
    val comparable: Boolean,
    /** Причины, по которым запуски нельзя сравнивать как «до/после». */
    val reasons: List<String>,
    /** Справочные замечания, не блокирующие сравнение (например, другая версия архива). */
    val notes: List<String> = emptyList(),
    /** Истина только для сравнимых полных запусков: исчезнувшие находки можно считать исправленными. */
    val fixConfirmed: Boolean,
    val added: List<JsonNode>,
    val unchanged: List<JsonNode>,
    val resolved: List<JsonNode>,
)

/**
 * Сравнение двух запусков. Отпечаток находки включает хэш всего файла, поэтому правка соседней строки меняет его;
 * для сравнения используется устойчивый ключ группы (категория, класс, путь, нормализованное описание;
 * для SCA - group:artifact:version:advisory) и сопоставление внутри группы по ближайшей строке.
 */
object RunComparator {
    fun groupKey(f: JsonNode): String {
        val category = f.path("category").asText()
        val path = f.path("path").asText()
        return when (category) {
            "SCA" -> listOf(category, f.path("group").asText(), f.path("artifact").asText(), f.path("version").asText(),
                f.path("advisoryId").asText(), path).joinToString("|")
            "SAST" -> listOf(category, f.path("class").asText(), path, f.path("rule").asText(),
                normalize(f.path("description").asText())).joinToString("|")
            else -> listOf(category, f.path("class").asText(), path).joinToString("|")
        }
    }

    private fun normalize(text: String) = text.replace(Regex("""\d+"""), "#").replace(Regex("""\s+"""), " ").trim()

    data class Diff(val added: List<JsonNode>, val unchanged: List<JsonNode>, val resolved: List<JsonNode>)

    fun diff(base: List<JsonNode>, head: List<JsonNode>): Diff {
        val baseGroups = base.groupBy(::groupKey).mapValues { (_, v) -> v.sortedBy { it.path("line").asInt() }.toMutableList() }
        val added = mutableListOf<JsonNode>()
        val unchanged = mutableListOf<JsonNode>()
        for ((key, items) in head.groupBy(::groupKey)) {
            val pool = baseGroups[key]
            for (item in items.sortedBy { it.path("line").asInt() }) {
                val match = pool?.minByOrNull { abs(it.path("line").asInt() - item.path("line").asInt()) }
                if (match == null) added.add(item) else { pool.remove(match); unchanged.add(item) }
            }
        }
        val resolved = baseGroups.values.flatten()
        val order = compareBy<JsonNode>({ it.path("path").asText() }, { it.path("line").asInt() })
        return Diff(added.sortedWith(order), unchanged.sortedWith(order), resolved.sortedWith(order))
    }

    /** ZIP-проект: два архива одного сценария сравнимы, хэш архива у новой версии иной. */
    fun notes(base: CompareSide, head: CompareSide): List<String> = buildList {
        if (base.kind == "archive" && head.kind == "archive" && base.inputHash != head.inputHash)
            add("Другая версия архива: сравниваются две версии одного проекта.")
    }

    fun reasons(base: CompareSide, head: CompareSide): List<String> = buildList {
        if (base.runId == head.runId) add("Выбран один и тот же запуск.")
        for (side in listOf("Базовый" to base, "Новый" to head)) {
            val (title, run) = side
            if (run.status != RunStatus.SUCCESS) add("$title запуск не завершился успешно (${run.status}).")
            else if (run.coverageStatus != "COMPLETE") add("$title запуск покрыт не полностью (${run.coverageStatus}).")
        }
        if (base.workflowId != head.workflowId || base.workflowVersion != head.workflowVersion)
            add("Запуски выполнены по разным версиям сценария.")
        if (base.kind != head.kind || base.repoUrl != head.repoUrl || base.subdir != head.subdir)
            add("Источники разные: другой репозиторий, тип источника или подпапка.")
        if (base.rulesVersion == null || base.rulesVersion != head.rulesVersion)
            add("Версии правил различаются: часть изменений может объясняться новыми правилами.")
    }
}

@Service
class RunCompareService(private val runs: RunStore) : TelegramRunHistory {
    override fun previous(runId: String, current: List<JsonNode>?): TelegramPreviousRun? {
        val previous = runs.previousComplete(runId) ?: return null
        val added = current?.let { RunComparator.diff(findingsOf(requireNotNull(previous.report)), it).added }.orEmpty()
        return TelegramPreviousRun(previous.id, added)
    }

    fun compare(baseId: String, headId: String): CompareResult {
        val base = runs.get(baseId)
        val head = runs.get(headId)
        val baseSide = side(base)
        val headSide = side(head)
        val reasons = RunComparator.reasons(baseSide, headSide)
        val diff = RunComparator.diff(base.report?.let(::findingsOf).orEmpty(), head.report?.let(::findingsOf).orEmpty())
        return CompareResult(baseSide, headSide, reasons.isEmpty(), reasons, RunComparator.notes(baseSide, headSide), reasons.isEmpty(),
            diff.added, diff.unchanged, diff.resolved)
    }

    private fun side(run: RunRecord): CompareSide {
        val revision = run.nodeRuns.mapNotNull { n ->
            (n.output["revision"] as? JsonNode)
                ?: (n.output["revision"] as? Map<*, *>)?.let { ObjectMapper().valueToTree<JsonNode>(it) }
        }.firstOrNull()
        val kind = when {
            revision?.hasNonNull("commitSha") == true -> "repo"
            revision?.hasNonNull("inputHash") == true -> "archive"
            else -> run.trigger.path("source").path("kind").textValue()
        }
        return CompareSide(
            run.id, run.status, run.coverageStatus.takeUnless { run.status == RunStatus.RUNNING }, kind,
            revision?.path("repoUrl")?.textValue() ?: run.trigger.path("source").path("url").textValue(),
            revision?.path("commitSha")?.textValue(),
            run.report?.path("inputHash")?.textValue() ?: revision?.path("inputHash")?.textValue(),
            revision?.path("subdir")?.asText().orEmpty(),
            run.report?.path("rulesVersion")?.textValue(),
            run.workflowId, run.workflowVersion, run.startedAt.toString(),
        )
    }
}

@RestController
@RequestMapping("/api")
class RunCompareController(private val service: RunCompareService) {
    @GetMapping("/runs/compare")
    fun compare(@RequestParam base: String, @RequestParam head: String): CompareResult = service.compare(base, head)
}
