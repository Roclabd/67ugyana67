package workflow.analyzers.sast

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import codeguard.analyzers.model.Endpoint
import codeguard.analyzers.model.ParameterSource
import codeguard.analyzers.model.ProjectModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import workflow.engine.NodeCategory
import workflow.engine.NodeContext
import workflow.engine.NodeDefinition
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import workflow.engine.PortSpec
import workflow.engine.PortType
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat
import java.util.UUID
import java.util.concurrent.TimeUnit

@Configuration(proxyBeanMethods = false)
class ProofConfiguration {
    @Bean
    fun proofNode(@Value("\${SANDBOX_IMAGE:codeguard-sandbox}") image: String): NodeDefinition = ProofNode(DockerSandbox(image))
}

/** Итог теста-доказательства. Не «подтверждено» и не «опровергнуто» — отдельные статусы для ошибок и таймаута. */
enum class ProofStatus { REPRODUCED, NOT_REPRODUCED, NOT_SUPPORTED, ERROR, TIMEOUT }

data class ProofCase(val findingId: String, val fingerprint: String, val sastClass: String, val test: String, val source: String)

/**
 * Генератор тестов-доказательств для SAST-находок Spring-проекта (MockMvc + spring-security-test).
 * Тест проходит, только если уязвимость воспроизводится на собранном приложении. Поиск остаётся за анализатором:
 * тест строится из находки, маршрута из модели проекта и тестовых данных проекта (data.sql).
 */
object ProofPlanner {
    private val endpointNote = Regex("""эндпоинт (GET|POST|PUT|DELETE|PATCH) (\S+)""")
    private val readNote = Regex("""чтение (\w+) без условия по (\w+)""")

    fun plan(findings: List<JsonNode>, model: ProjectModel): Pair<List<ProofCase>, List<Map<String, Any>>> {
        val app = applicationClass(model)
        val cases = mutableListOf<ProofCase>()
        val skipped = mutableListOf<Map<String, Any>>()
        for ((index, finding) in findings.withIndex()) {
            if (finding.path("category").asText() != "SAST") continue
            val id = finding.path("id").asText()
            val cls = finding.path("class").asText()
            val name = "Proof${index + 1}"
            val body = when {
                app == null -> null
                cls == "route-authorization" -> routeAuthorization(finding)
                cls == "object-authorization" -> objectAuthorization(finding, model)
                cls == "sql-injection" -> sqlInjection(finding, model)
                else -> null
            }
            if (body == null) {
                skipped += mapOf("findingId" to id, "class" to cls, "status" to ProofStatus.NOT_SUPPORTED.name,
                    "details" to if (app == null) "Не найден класс @SpringBootApplication" else "Шаблона теста для этого класса или маршрута нет")
                continue
            }
            cases += ProofCase(id, finding.path("fingerprint").asText(), cls, name, testClass(name, app!!, body))
        }
        return cases to skipped
    }

    private fun applicationClass(model: ProjectModel): String? = model.files.firstNotNullOfOrNull { file ->
        if (!file.path.endsWith(".kt") || "@SpringBootApplication" !in file.text) return@firstNotNullOfOrNull null
        val pkg = Regex("""(?m)^package\s+([\w.]+)""").find(file.text)?.groupValues?.get(1)
        val cls = Regex("""@SpringBootApplication[\s\S]*?class\s+(\w+)""").find(file.text)?.groupValues?.get(1) ?: return@firstNotNullOfOrNull null
        listOfNotNull(pkg, cls).joinToString(".")
    }

    /** Открытый маршрут: запрос без входа должен вернуть данные (200), хотя ниже есть правило строже. */
    private fun routeAuthorization(finding: JsonNode): String? {
        val match = finding.path("evidence").firstNotNullOfOrNull { endpointNote.find(it.path("note").asText()) } ?: return null
        val (method, path) = match.destructured
        if (method != "GET" || '{' in path) return null
        return """
            mvc.perform(get("$path")).andExpect(status().isOk)
        """
    }

    /** IDOR: пользователь-владелец одной записи читает чужую запись по идентификатору и получает её. */
    private fun objectAuthorization(finding: JsonNode, model: ProjectModel): String? {
        val evidence = finding.path("evidence").toList()
        val (table, ownerColumn) = evidence.firstNotNullOfOrNull { readNote.find(it.path("note").asText())?.destructured }
            ?.let { it.component1() to it.component2() } ?: return null
        val handler = evidence.firstOrNull()?.let { endpointAt(model, it.path("path").asText(), it.path("line").asInt()) } ?: return null
        if (handler.method != "GET") return null
        val idParam = handler.parameters.firstOrNull { it.source == ParameterSource.PATH_VARIABLE } ?: return null
        val rows = rows(model, table)
        val columns = model.sqlSchema.tables[table]?.columns?.keys?.toList() ?: return null
        val ownerIndex = columns.indexOf(ownerColumn).takeIf { it >= 0 } ?: return null
        val first = rows.firstOrNull() ?: return null
        val other = rows.firstOrNull { it.getOrNull(ownerIndex) != first.getOrNull(ownerIndex) } ?: return null
        val path = handler.path?.replace("{${idParam.bindingName ?: idParam.name}}", other[0]) ?: return null
        return """
            mvc.perform(get("$path").with(user("${first[ownerIndex]}").roles("USER", "CUSTOMER")))
                .andExpect(status().isOk)
                .andExpect(content().string(containsString("${other[ownerIndex]}")))
        """
    }

    /** SQL-инъекция: обычное значение ничего не находит, значение с `' OR '1'='1` возвращает чужие строки. */
    private fun sqlInjection(finding: JsonNode, model: ProjectModel): String? {
        val handler = endpointAt(model, finding.path("path").asText(), finding.path("line").asInt()) ?: return null
        if (handler.method != "GET" || handler.path == null || '{' in handler.path!!) return null
        val param = handler.parameters.firstOrNull { it.source == ParameterSource.REQUEST_PARAM } ?: return null
        val name = param.bindingName ?: param.name
        return """
            val who = user("proof-user").roles("USER", "CUSTOMER")
            mvc.perform(get("${handler.path}").param("$name", "zz_proof_no_match").with(who))
                .andExpect(status().isOk).andExpect(content().json("[]"))
            val injected = mvc.perform(get("${handler.path}").param("$name", "zz_proof_no_match' OR '1'='1").with(who))
                .andExpect(status().isOk).andReturn().response.contentAsString
            check(injected.trim() != "[]") { "Инъекция не вернула строк" }
        """
    }

    private fun endpointAt(model: ProjectModel, path: String, line: Int): Endpoint? =
        model.spring.endpoints.filter { it.location.path == path && it.location.line <= line }.maxByOrNull { it.location.line }

    /** Строки INSERT INTO <table> VALUES (...) из data.sql — значения как текст, без кавычек. */
    private fun rows(model: ProjectModel, table: String): List<List<String>> {
        val text = model.files.filter { it.path.endsWith("data.sql") }.joinToString("\n") { it.text }
        val insert = Regex("""(?is)INSERT\s+INTO\s+$table\s+VALUES\s*(.+?);""").findAll(text)
        return insert.flatMap { block ->
            Regex("""\(([^()]*)\)""").findAll(block.groupValues[1]).map { tuple ->
                tuple.groupValues[1].split(',').map { it.trim().removeSurrounding("'") }
            }
        }.toList()
    }

    private fun testClass(name: String, app: String, body: String) = """
        package proof

        import org.hamcrest.Matchers.containsString
        import org.junit.jupiter.api.BeforeEach
        import org.junit.jupiter.api.Test
        import org.springframework.beans.factory.annotation.Autowired
        import org.springframework.boot.test.context.SpringBootTest
        import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
        import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
        import org.springframework.test.web.servlet.MockMvc
        import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
        import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
        import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
        import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
        import org.springframework.test.web.servlet.setup.MockMvcBuilders
        import org.springframework.web.context.WebApplicationContext

        @SpringBootTest(classes = [$app::class])
        class $name {
            @Autowired lateinit var context: WebApplicationContext
            lateinit var mvc: MockMvc

            @BeforeEach
            fun setUp() {
                mvc = MockMvcBuilders.webAppContextSetup(context).apply<DefaultMockMvcBuilder>(springSecurity()).build()
            }

            @Test
            fun reproduces() {
                ${body.trimIndent().replace("\n", "\n                ")}
            }
        }
    """.trimIndent() + "\n"
}

/** Запуск тестов-доказательств в контейнере. Без Docker — отказ, на хосте чужой код не исполняется. */
open class DockerSandbox(private val image: String) {
    data class Outcome(val results: Map<String, ProofStatus>, val error: String?)

    open fun run(project: Path, cases: List<ProofCase>, work: Path, timeoutSeconds: Long): Outcome {
        val proofs = Files.createDirectories(work.resolve("proofs/proof"))
        val out = Files.createDirectories(work.resolve("proof-results"))
        cases.forEach { Files.writeString(proofs.resolve("${it.test}.kt"), it.source) }
        val name = "codeguard-proof-" + UUID.randomUUID().toString().take(8)
        val script = "cp -r /src/. /tmp/w && cd /tmp/w && chmod +x gradlew && " +
            "./gradlew --offline --no-daemon -q test -PorganizerTests=/proofs --tests 'proof.*' > /out/gradle.log 2>&1; " +
            "cp build/test-results/test/*.xml /out/ 2>/dev/null; true"
        val command = listOf("docker", "run", "--rm", "--name", name, "--network", "none",
            "--cpus", "2", "--memory", "3g", "--pids-limit", "512", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,exec,size=2g",
            "-v", "${project.toAbsolutePath()}:/src:ro", "-v", "${work.resolve("proofs").toAbsolutePath()}:/proofs:ro",
            "-v", "${out.toAbsolutePath()}:/out", "-v", "codeguard-sandbox-gradle:/home/sandbox/.gradle",
            image, "sh", "-c", script)
        val process = try {
            ProcessBuilder(command).redirectErrorStream(true).redirectOutput(work.resolve("docker.log").toFile()).start()
        } catch (_: Exception) {
            return Outcome(emptyMap(), "Песочница недоступна: Docker не запущен")
        }
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            runCatching { ProcessBuilder("docker", "kill", name).start().waitFor(10, TimeUnit.SECONDS) }
            process.destroyForcibly()
            return Outcome(cases.associate { it.test to ProofStatus.TIMEOUT }, "Истекло время песочницы ($timeoutSeconds с)")
        }
        if (process.exitValue() != 0) return Outcome(emptyMap(), "Песочница не запустилась (код ${process.exitValue()})")
        val results = cases.associate { case ->
            val xml = out.resolve("TEST-proof.${case.test}.xml")
            val status = when {
                !Files.exists(xml) -> ProofStatus.ERROR
                Files.readString(xml).let { "<failure" in it || "<error" in it } -> ProofStatus.NOT_REPRODUCED
                else -> ProofStatus.REPRODUCED
            }
            case.test to status
        }
        val compileFailed = results.values.all { it == ProofStatus.ERROR }
        return Outcome(results, if (compileFailed) "Тесты не собрались или проект не собрался — см. журнал песочницы" else null)
    }
}

/**
 * Нода «Тест-доказательство (песочница)»: для SAST-находок строит MockMvc-тесты и запускает их в изолированном
 * контейнере. Итог привязан к хэшу проверенных файлов проекта; «воспроизведено» выдаёт только сервер по результату теста.
 */
class ProofNode(private val sandbox: DockerSandbox) : NodeDefinition {
    override val type = "proof.sandbox"
    override val title = "Тест-доказательство (песочница)"
    override val description = "Строит тесты MockMvc для находок SAST и запускает их в контейнере без сети: воспроизводится ли уязвимость"
    override val category = NodeCategory.LOGIC
    override val inputs = listOf(
        PortSpec("workspace", PortType.WORKSPACE), PortSpec("model", PortType.PROJECT_MODEL), PortSpec("findings", PortType.FINDINGS),
    )
    override val outputs = listOf(PortSpec("proofs", PortType.ANY))
    override val paramsSchema: JsonNode = ObjectMapper().readTree(
        """{"type":"object","properties":{"timeoutSeconds":{"type":"integer","minimum":30,"maximum":600,"title":"Сколько ждать песочницу, с"}},"additionalProperties":false}""",
    )

    override suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput = withContext(Dispatchers.IO) {
        val project = input.ports["workspace"] as? Path ?: return@withContext NodeOutput(emptyMap(), NodeStatus.FAILED)
        val model = input.ports["model"] as? ProjectModel ?: return@withContext NodeOutput(emptyMap(), NodeStatus.FAILED)
        val json = ObjectMapper()
        val findings = json.valueToTree<JsonNode>(input.ports["findings"]).let { if (it.isArray) it.toList() else it.path("findings").toList() }
        val (cases, unsupported) = ProofPlanner.plan(findings, model)
        val hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
            model.files.sortedBy { it.path }.joinToString("\n") { "${it.path}:${it.sha256}" }.toByteArray(),
        ))
        if (cases.isEmpty()) {
            return@withContext NodeOutput(mapOf("proofs" to mapOf("projectHash" to hash, "results" to unsupported)), NodeStatus.SUCCESS)
        }
        val work = Files.createDirectories(requireNotNull(ctx.workspace).resolve("${ctx.nodeId}-sandbox"))
        ctx.log("Тестов-доказательств: ${cases.size}, запуск в контейнере без сети")
        val outcome = sandbox.run(project, cases, work, ctx.params.path("timeoutSeconds").asLong(300))
        outcome.error?.let(ctx::log)
        val results = cases.map { case ->
            mapOf("findingId" to case.findingId, "fingerprint" to case.fingerprint, "class" to case.sastClass, "test" to case.test,
                "status" to (outcome.results[case.test] ?: ProofStatus.ERROR).name, "source" to case.source)
        } + unsupported
        val ok = outcome.error == null && outcome.results.values.none { it == ProofStatus.ERROR || it == ProofStatus.TIMEOUT }
        NodeOutput(mapOf("proofs" to mapOf("projectHash" to hash, "results" to results, "error" to outcome.error)),
            if (ok) NodeStatus.SUCCESS else NodeStatus.PARTIAL)
    }
}

