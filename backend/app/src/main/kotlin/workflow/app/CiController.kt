package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ClassPathResource
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.*
import workflow.engine.RunStatus
import workflow.nodes.InputRejected
import java.security.MessageDigest
import java.util.HexFormat
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class CiRequest(val repoUrl: String, val commitSha: String, val branch: String? = null, val rulesVersion: String? = null)
data class GateDecision(val pass: Boolean, val reason: String, val missingAnalyzers: List<String> = emptyList())

/** Старые значения вида «<префикс>-rules-vN» принимаются как «codeguard-rules-vN». */
private val LEGACY_RULES = Regex("""^[a-z]+(?:-[a-z]+)?-rules-v([0-9]+)$""")
private fun currentRulesName(part: String): String = LEGACY_RULES.replace(part, "codeguard-rules-v$1")

object CiGate {
    fun decide(run: RunRecord, sha: String, expectedVersion: String?, requestedVersion: String? = null): GateDecision {
        val report = run.report
        val expected = expectedVersion?.split('+')?.map(::currentRulesName)?.let(::rulesVersionSignature)
        val requested = requestedVersion?.split('+')?.map(::currentRulesName)?.let(::rulesVersionSignature)
        val reason = when {
            run.status != RunStatus.SUCCESS -> "RUN_${run.status}"
            run.coverageStatus != "COMPLETE" || report?.path("coverage")?.path("status")?.asText() != "COMPLETE" ->
                "INCOMPLETE_ANALYSIS"
            !run.commitsVerified || run.trigger.path("commitSha").textValue() != sha ||
                report.path("inputHash").textValue() != sha -> "COMMIT_MISMATCH"
            expected == null || (requestedVersion != null && requested != expected) ||
                rulesVersionSignature(run.rulesVersions) != expected ||
                report.path("rulesVersion").textValue() != expected -> "RULES_VERSION_MISMATCH"
            missingAnalyzers(report).isNotEmpty() -> return GateDecision(false, "MISSING_ANALYZERS", missingAnalyzers(report))
            run.counts["CRITICAL"] == null -> "INCOMPLETE_ANALYSIS"
            run.counts.getValue("CRITICAL") > 0 -> "CRITICAL_FINDINGS"
            else -> return GateDecision(true, "PASS")
        }
        return GateDecision(false, reason)
    }

    /** Для прохождения гейта в отчёте должны быть завершённые SECRET, SCA и SAST (analyzerTypes + byAnalyzer). */
    fun missingAnalyzers(report: JsonNode?): List<String> {
        val coverage = report?.path("coverage")
        val types = coverage?.path("analyzerTypes")
        val byAnalyzer = coverage?.path("byAnalyzer")
        val present = hashSetOf<String>()
        types?.fields()?.forEach { (nodeId, type) ->
            val status = byAnalyzer?.path(nodeId)?.path("status")?.asText().orEmpty()
            if (status.isNotEmpty() && status != "FAILED") {
                when (type.asText()) {
                    "analyzer.secret", "analyzer.secret.regex" -> present += "SECRET"
                    "analyzer.sca" -> present += "SCA"
                    "analyzer.sast" -> present += "SAST"
                }
            }
        }
        return listOf("SECRET", "SCA", "SAST").filter { it !in present }
    }
}

class Unauthorized : RuntimeException()

@Component
class HookToken(@Value("\${CI_TOKEN:}") private val token: String) {
    fun check(authorization: String?) {
        val provided = authorization?.takeIf { it.startsWith("Bearer ") }?.substring(7)
        if (token.isBlank() || provided.isNullOrBlank() || !MessageDigest.isEqual(hash(token), hash(provided))) {
            throw Unauthorized()
        }
    }

    fun checkGithub(signature: String?, body: ByteArray) {
        val raw = signature?.removePrefix("sha256=")
        if (token.isBlank() || signature == raw || raw == null || !Regex("[0-9a-fA-F]{64}").matches(raw)) {
            throw Unauthorized()
        }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(token.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        if (!MessageDigest.isEqual(mac.doFinal(body), HexFormat.of().parseHex(raw))) throw Unauthorized()
    }
    private fun hash(text: String) = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
}

@RestController
@RequestMapping("/api")
class CiController(
    private val runs: RunService,
    private val workflows: WorkflowStore,
    private val json: ObjectMapper,
    private val token: HookToken,
    @Value("\${CI_RULES_VERSION:}") private val rulesVersion: String,
    @Value("\${RUN_TIMEOUT_SECONDS:240}") private val runTimeoutSeconds: Long = RunService.AI_RUN_SECONDS,
) {
    @PostMapping("/ci/workflows/{id}/run")
    fun run(
        @PathVariable id: String,
        @RequestHeader("Authorization", required = false) authorization: String?,
        @RequestParam(defaultValue = "false") wait: Boolean,
        @RequestBody request: CiRequest,
    ): ResponseEntity<Map<String, Any?>> {
        token.check(authorization)
        val ticket = runs.start(id, ciTrigger(request))
        if (!wait) return ResponseEntity.accepted().body(
            mapOf("runId" to ticket.id, "status" to "RUNNING", "coverageStatus" to "PARTIAL",
                "pass" to false, "reason" to "RUN_RUNNING"),
        )
        val run = runBlocking { withTimeoutOrNull(waitMillis(runTimeoutSeconds)) { ticket.completion.await() } }
            ?: return ResponseEntity.status(504).body(
                mapOf("runId" to ticket.id, "status" to "RUNNING", "coverageStatus" to "PARTIAL",
                    "pass" to false, "reason" to "RUN_TIMEOUT"),
            )
        val result = CiGate.decide(run, request.commitSha, rulesVersion, request.rulesVersion)
        return ResponseEntity.ok(mapOf("runId" to run.id, "status" to run.status, "coverageStatus" to run.coverageStatus,
            "counts" to run.counts.takeIf { it.isNotEmpty() }, "pass" to result.pass, "reason" to result.reason,
            "missingAnalyzers" to result.missingAnalyzers.takeIf { it.isNotEmpty() }))
    }

    @PostMapping("/webhooks/{id}")
    fun webhook(
        @PathVariable id: String,
        @RequestHeader("Authorization", required = false) authorization: String?,
        @RequestHeader("X-GitHub-Event", required = false) event: String?,
        @RequestHeader("X-Hub-Signature-256", required = false) signature: String?,
        @RequestBody(required = false) body: ByteArray?,
    ): ResponseEntity<Map<String, String>> {
        val bytes = body ?: ByteArray(0)
        if (bytes.size > 2 * 1024 * 1024) throw InputRejected("Событие превышает 2 МБ")
        if (authorization == null && event != null) token.checkGithub(signature, bytes)
        else token.check(authorization)
        if (event == "ping") return ResponseEntity.ok(mapOf("status" to "OK"))
        val payload: JsonNode? = if (event != null && bytes.isNotEmpty()) try {
            json.readTree(bytes)
        } catch (_: Exception) {
            throw InputRejected("Проверьте JSON события")
        } else null
        val data = when (event) {
            "push" -> {
                val push = payload ?: throw InputRejected("Нет данных события push")
                ciTrigger(CiRequest(push.path("repository").path("html_url").asText(), push.path("after").asText(),
                    push.path("ref").asText().removePrefix("refs/heads/")))
            }
            "pull_request" -> {
                val head = payload?.path("pull_request")?.path("head") ?: throw InputRejected("Нет данных Pull Request")
                ciTrigger(CiRequest(head.path("repo").path("html_url").asText(), head.path("sha").asText(),
                    head.path("ref").asText()))
            }
            null -> json.createObjectNode().put("kind", "webhook")
            else -> throw InputRejected("Поддерживаются события push и pull_request")
        }
        return ResponseEntity.accepted().body(mapOf("runId" to runs.start(id, data).id))
    }

    @GetMapping("/ci/workflows/{id}/config", produces = ["text/yaml;charset=UTF-8"])
    fun config(@PathVariable id: String, @RequestParam kind: String): String {
        workflows.get(id)
        val filename = when (kind) {
            "github" -> "github-actions.yml"
            "gitlab" -> "gitlab-ci.yml"
            else -> throw InputRejected("Укажите kind=github или kind=gitlab")
        }
        return ClassPathResource("ci/$filename").getContentAsString(Charsets.UTF_8).replace("WORKFLOW_ID_HERE", id)
    }

    companion object {
        /** Ожидание CI = максимальный бюджет запуска с ИИ (без ожидания решений) + небольшой запас. */
        fun waitMillis(runTimeoutSeconds: Long): Long = RunService.runBudgetMillis(true, runTimeoutSeconds, 0) + 5_000
    }

    private fun ciTrigger(request: CiRequest): JsonNode {
        if (!Regex("[a-f0-9]{40}").matches(request.commitSha) || request.commitSha.all { it == '0' } ||
            (request.branch?.length ?: 0) > 300) throw InputRejected("Укажите SHA коммита и корректную ветку")
        return json.createObjectNode().put("kind", "webhook").put("commitSha", request.commitSha)
            .put("branch", request.branch).apply { putObject("source").put("kind", "repo").put("url", request.repoUrl) }
    }
}
