package ru.codeguard.ai.cli

import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import ru.codeguard.ai.AiExplainer
import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.llm.AiLog
import ru.codeguard.ai.llm.FileResponseCache
import ru.codeguard.ai.llm.LlmConfig
import ru.codeguard.ai.llm.OpenAiCompatibleClient
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.ai.model.AiLocation
import ru.codeguard.sast.SastAnalyzer
import ru.codeguard.sast.project.SastProjectLoader
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess

/**
 * Живой прогон AI-слоя: gradle explain --args="<каталог проекта> [--truth <ground-truth.json>]".
 * Находки — SAST (наш модуль). --truth подмешивает SECRET и SCA из эталона авторов набора, пока анализаторы C не готовы.
 * LLM — из переменных LLM_BASE_URL, LLM_MODEL, LLM_API_KEY. Кэш ответов — LLM_CACHE_DIR (по умолчанию data/llm-cache).
 */
fun main(args: Array<String>) {
    val err = PrintStream(System.err, true, Charsets.UTF_8)
    if (args.isEmpty()) {
        err.println("Использование: explain <каталог проекта> [--truth <ground-truth.json>] [--db <vulnerabilities.json>]")
        exitProcess(2)
    }
    val root = Paths.get(args[0])
    val truth = args.indexOf("--truth").takeIf { it >= 0 }?.let { Paths.get(args[it + 1]) }
    val dbPath = args.indexOf("--db").takeIf { it >= 0 }?.let { Paths.get(args[it + 1]) }
        ?: Paths.get("fixtures/training/vulnerability-database/vulnerabilities.json")

    val project = SastProjectLoader.load(root)
    val sast = SastAnalyzer().analyze(project)
    var n = 0
    val findings = sast.findings.map { f ->
        AiFinding(
            id = "f-${++n}", category = "SAST", findingClass = f.sastClass, severity = f.severity.name, path = f.path, line = f.line, endLine = f.endLine,
            title = f.title, description = f.description, remediation = f.remediation,
            evidence = f.evidence.map { AiLocation(it.path, it.line, it.endLine, it.note) },
        )
    } + (truth?.let { fromGroundTruth(it, n) } ?: emptyList())

    // .env в корне репозитория (в .gitignore) — для ключа провайдера; переменные окружения процесса важнее.
    val config = LlmConfig.fromEnv(LlmConfig.loadDotEnv(Paths.get(".env")) + System.getenv())
    err.println("LLM: ${config ?: "не настроена — объяснения не будут получены"}")
    val explainer = AiExplainer(
        client = config?.let { OpenAiCompatibleClient(it) },
        source = { p -> runCatching { Files.readString(root.resolve(p)) }.getOrNull() },
        advisories = Advisories.load(dbPath),
        cache = FileResponseCache(Paths.get(System.getenv("LLM_CACHE_DIR") ?: "data/llm-cache")),
        log = AiLog.STDERR,
    )
    val result = explainer.explain(findings)

    val json = jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
    PrintStream(System.out, true, Charsets.UTF_8).println(json.writeValueAsString(mapOf("findings" to findings.map { it to result.findings[it.id] }.map { (f, ai) -> mapOf("id" to f.id, "class" to (f.findingClass ?: f.advisoryId), "path" to f.path, "line" to f.line, "ai" to ai) }, "ai" to result.report, "usefulness" to result.usefulness)))

    val r = result.report
    val v = r.validator
    err.println("AI: ${r.status}${r.reason?.let { " — $it" } ?: ""}")
    err.println("Валидатор: ответов ${v.responses}, ошибок схемы ${v.schemaFailures}, повторов ${v.retries}, из кэша ${v.cacheHits}, отброшено ссылок на находки ${v.rejectedFindingRefs}, вырезано CVE ${v.rejectedCves}, вырезано мест ${v.rejectedLocations}, отброшено чужих версий ${v.rejectedVersions}, отклонено попыток оспорить находку ${v.rejectedDisputes}")
    val u = result.usefulness
    err.println("Полезность: рекомендаций ${u.recommendations}, с примером ${u.withFixExample}, пример разбирается ${u.fixParses}, правильный признак исправления ${u.fixPatternOk}, перепроверка SAST чистая ${u.rerunClean}; SCA: целевая версия безопасна ${u.scaTargetSafe}/${u.scaTotal}")
}

/** SECRET и SCA из эталона авторов набора — временная подстановка вместо анализаторов C. */
private fun fromGroundTruth(path: Path, offset: Int): List<AiFinding> {
    val root = jacksonObjectMapper().readTree(path.toFile())
    var n = offset
    return root.path("findings").filter { it.path("category").asText() in setOf("SECRET", "SCA") }.map { f ->
        val cat = f.path("category").asText()
        val fixed = Regex("→ `([^`]+)`").find(f.path("affected").asText(""))?.groupValues?.get(1)
        AiFinding(
            id = "f-${++n}", category = cat, findingClass = if (cat == "SECRET") f.path("class").asText() else null,
            severity = f.path("severity").asText(), path = f.path("path").asText(), line = f.path("line").asInt(), endLine = f.path("endLine").asInt().takeIf { it > 0 },
            title = if (cat == "SCA") "${f.path("group").asText()}:${f.path("artifact").asText()} ${f.path("version").asText()}" else f.path("class").asText(),
            description = f.path("description").asText(null),
            secretMasked = if (cat == "SECRET") "••••" else null,
            // Места, где задана версия/продолжается проблема (gradle.properties для org.json и т. п.) — как evidence анализатора.
            evidence = f.path("alternateLocations").map { a -> AiLocation(a.path("path").asText(), a.path("line").asInt(), a.path("endLine").asInt().takeIf { it > 0 }, "связанное место") },
            group = f.path("group").asText(null), artifact = f.path("artifact").asText(null), version = f.path("version").asText(null),
            advisoryId = f.path("advisoryIds").firstOrNull()?.asText(), fixedVersions = listOfNotNull(fixed),
        )
    }
}
