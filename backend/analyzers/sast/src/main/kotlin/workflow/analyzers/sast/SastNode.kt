package workflow.analyzers.sast

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import ru.codeguard.sast.SastAnalyzer
import ru.codeguard.sast.model.CoverageStatus
import ru.codeguard.sast.model.SastClass
import ru.codeguard.sast.model.SastCoverage
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Severity
import ru.codeguard.sast.project.KotlinSource
import ru.codeguard.sast.project.ParseError
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import workflow.engine.ruCount
import java.security.MessageDigest
import java.util.HexFormat

@Configuration(proxyBeanMethods = false)
class SastConfiguration {
    @Bean
    fun sastNode(): NodeDefinition = SastNode()
}

/**
 * Нода «SAST: Kotlin + Spring» — адаптер собственного SAST (ru.codeguard.sast) к SPI движка.
 * Вход — ProjectModel из ноды «Разбор проекта», выход — находки в форме contracts/finding.schema.json.
 * Параметры: классы проверок (по умолчанию все пять) и порог критичности.
 */
class SastNode : NodeDefinition {
    override val type = "analyzer.sast"
    override val title = "SAST: Kotlin + Spring"
    override val description = "SQL-инъекции, отключённая проверка TLS, CORS с credentials, затенённые правила доступа, чтение чужих объектов"
    override val category = NodeCategory.ANALYZER
    override val inputs = listOf(PortSpec("model", PortType.PROJECT_MODEL))
    override val outputs = listOf(PortSpec("findings", PortType.FINDINGS))
    override val paramsSchema: JsonNode = JsonNodeFactory.instance.objectNode().apply {
        put("type", "object")
        put("additionalProperties", false)
        val properties = putObject("properties")
        properties.putObject("classes").apply {
            put("type", "array")
            put("title", "Классы проверок")
            put("uniqueItems", true)
            putObject("items").put("type", "string").putArray("enum").apply { RULE_BY_CLASS.keys.forEach { add(it) } }
            putArray("default").apply { RULE_BY_CLASS.keys.forEach { add(it) } }
        }
        properties.putObject("minSeverity").put("type", "string").put("title", "Порог критичности").put("default", "LOW")
            .putArray("enum").apply { Severity.entries.forEach { add(it.name) } }
    }

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.Default) {
        val model = input.ports["model"] as? ProjectModel ?: return@withContext failed("На вход не пришла модель проекта")
        val classes = ctx.params.path("classes").takeIf { it.isArray }?.map { it.asText() }?.toSet() ?: RULE_BY_CLASS.keys
        val rules = SastAnalyzer.DEFAULT_RULES.filter { rule -> RULE_BY_CLASS.any { (cls, id) -> id == rule.id && cls in classes } }
        val minSeverity = runCatching { Severity.valueOf(ctx.params.path("minSeverity").asText("LOW")) }.getOrDefault(Severity.LOW)

        val result = SastAnalyzer(rules).analyze(SastProjectAdapter.from(model))
        val findings = result.findings.filter { it.severity >= minSeverity }
        ctx.log("SAST: ${ruCount(findings.size, "находка", "находки", "находок")}, покрытие ${result.coverage.status}, ${ruCount(rules.size, "правило", "правила", "правил")}")
        val unsupported = model.languages.filter { !it.sastSupported && !it.script }
        val status = when (result.coverage.status) {
            CoverageStatus.COMPLETE -> if (unsupported.isEmpty()) NodeStatus.SUCCESS else NodeStatus.PARTIAL
            CoverageStatus.PARTIAL -> NodeStatus.PARTIAL
            CoverageStatus.FAILED -> NodeStatus.FAILED
        }
        NodeOutput(
            ports = mapOf("findings" to SastFindingsJson.toJson(findings, model)),
            status = status,
            coverage = coverageMap(result.coverage).let { base ->
                if (unsupported.isEmpty()) base else base + mapOf(
                    "status" to if (result.coverage.status == CoverageStatus.COMPLETE) "PARTIAL" else base["status"]!!,
                    "filesSkipped" to (base["filesSkipped"] as List<*> + unsupported.map { language ->
                        mapOf("path" to ".","reason" to "${language.name}-файлы не анализируются (${ruCount(language.files, "файл", "файла", "файлов")})")
                    }),
                )
            } + mapOf("languages" to model.languages.map {
                mapOf("name" to it.name, "files" to it.files, "sastSupported" to it.sastSupported)
            }),
            rulesVersion = SastAnalyzer.RULES_VERSION,
        )
    }

    private fun failed(reason: String) = NodeOutput(
        emptyMap(), NodeStatus.FAILED,
        coverageMap(SastCoverage(CoverageStatus.FAILED, 0, emptyList(), emptyList(),
            listOf(ru.codeguard.sast.model.Unresolved("input", "", null, reason)), emptyList())),
        SastAnalyzer.RULES_VERSION,
    )

    companion object {
        /** Код класса находки → id правила SAST. Порядок — порядок в форме параметров. */
        val RULE_BY_CLASS: Map<String, String> = linkedMapOf(
            SastClass.SQL_INJECTION to "sast.sql.taint-to-query",
            SastClass.TLS_VERIFICATION to "sast.tls.trust-all",
            SastClass.CREDENTIALED_CORS to "sast.cors.any-origin-with-credentials",
            SastClass.ROUTE_AUTHORIZATION to "sast.route.public-sensitive-route",
            SastClass.OBJECT_AUTHORIZATION to "sast.idor.read-by-id-without-owner",
        )

        /** Покрытие в форме $defs/coverage. Пустой путь (ошибка уровня проекта) — корень проекта «.». */
        fun coverageMap(c: SastCoverage): Map<String, Any> = mapOf(
            "status" to c.status.name,
            "filesAnalyzed" to c.filesAnalyzed,
            "filesSkipped" to c.filesSkipped.map { s ->
                buildMap { put("path", rootIfEmpty(s.path)); put("reason", s.reason); s.line?.let { put("line", it) } }
            },
            "rulesApplied" to c.rulesApplied,
            "unresolved" to c.unresolved.map { u ->
                buildMap {
                    put("kind", u.kind); put("path", rootIfEmpty(u.path)); u.line?.let { put("line", it) }
                    put("reason", u.reason); u.subject?.let { put("subject", it) }
                }
            },
            "dismissed" to c.dismissed.map { d ->
                buildMap { put("rule", d.rule); put("path", rootIfEmpty(d.path)); d.line?.let { put("line", it) }; put("reason", d.reason) }
            },
        )

        private fun rootIfEmpty(path: String) = path.ifEmpty { "." }
    }
}

/**
 * ProjectModel (модуль C) → SastProject. Тексты и PSI уже нормализованы моделью (BOM, CRLF → LF),
 * поэтому смещения PSI и номера строк совпадают с теми, что дал бы автономный загрузчик SAST.
 * Файл с синтаксической ошибкой модель не отдаёт в `kotlin`; SAST разбирает его сам (PSI устойчив к ошибкам)
 * и анализирует, а в покрытии он идёт как пропущенный — так же, как в автономном прогоне.
 */
object SastProjectAdapter {
    private val TEXT_TYPES = setOf(SourceType.SQL, SourceType.YAML, SourceType.PROPERTIES, SourceType.XML, SourceType.KOTLIN_SCRIPT)

    fun from(model: ProjectModel): SastProject {
        val kotlin = mutableListOf<KotlinSource>()
        val texts = mutableMapOf<String, SourceText>()
        val errors = mutableListOf<ParseError>()
        for (file in model.files) {
            when {
                file.type == SourceType.KOTLIN -> {
                    val psi = model.kotlin[file.path]
                    if (psi != null) {
                        kotlin += KotlinSource(SourceText(file.path, file.text), psi)
                    } else {
                        val (source, parseErrors) = SastProjectLoader.parseKotlin(file.path, file.text)
                        kotlin += source
                        errors += parseErrors.ifEmpty { listOf(ParseError(file.path, null, "Модель проекта не смогла разобрать файл")) }
                    }
                }
                file.type in TEXT_TYPES -> texts[file.path] = SourceText(file.path, file.text)
            }
        }
        // Файлы .kt, которые модель не смогла прочитать (кодировка, доступ), — тоже пропущенные.
        val read = model.files.mapTo(hashSetOf()) { it.path }
        model.parseErrors.filter { it.path.endsWith(".kt") && it.path !in read }
            .forEach { errors += ParseError(it.path, it.line, it.message) }
        return SastProject(kotlin, texts, errors)
    }
}

/** SastFinding → находка contracts/finding.schema.json. Отпечаток — по contracts/report-format.md. */
object SastFindingsJson {
    fun toJson(findings: List<SastFinding>, model: ProjectModel): ArrayNode {
        val fileHashes = model.files.associate { it.path to it.sha256 }
        val out = JsonNodeFactory.instance.arrayNode()
        val seen = hashMapOf<String, Int>()
        for (f in findings) {
            val fingerprint = fingerprint(f, fileHashes[f.path].orEmpty())
            // id уникален в запуске: одинаковый фрагмент в одном файле (редко) получает суффикс.
            val n = seen.merge(fingerprint, 1, Int::plus)!!
            val node = out.addObject()
                .put("id", if (n == 1) "sast-$fingerprint" else "sast-$fingerprint-$n")
                .put("fingerprint", fingerprint)
                .put("category", "SAST")
                .put("class", f.sastClass)
                .put("path", f.path)
                .put("line", f.line)
            f.endLine?.takeIf { it > f.line }?.let { node.put("endLine", it) }
            node.put("severity", f.severity.name)
                .put("rule", f.rule)
                .put("title", f.title)
                .put("description", f.description)
                .put("remediation", f.remediation)
            val evidence = node.putArray("evidence")
            for (e in f.evidence.ifEmpty { listOf(ru.codeguard.sast.model.Location(f.path, f.line, f.endLine)) }) {
                val item = evidence.addObject().put("path", e.path).put("line", e.line)
                e.endLine?.takeIf { it > e.line }?.let { item.put("endLine", it) }
                e.note?.let { item.put("note", it) }
            }
        }
        return out
    }

    /** SHA-256 однозначной сериализации (длина:значение) категории, класса, пути, нормализованного фрагмента и хэша файла. */
    fun fingerprint(f: SastFinding, fileSha256: String): String {
        val fields = listOf("SAST", f.sastClass, f.path, f.fragment, fileSha256)
        val bytes = fields.joinToString("") { it.length.toString() + ":" + it }.toByteArray(Charsets.UTF_8)
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}
