package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.CacheControl
import org.springframework.http.ContentDisposition
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import workflow.nodes.findingsOf
import java.net.InetAddress

/** Ресурс был, но больше недоступен (HTTP 410). */
class Gone(message: String) : RuntimeException(message)

/** Для находки нет автоисправления (HTTP 404 с пояснением). */
class NoAutofix(message: String) : RuntimeException(message)

@RestController
@RequestMapping("/api")
class ExportController(
    private val history: RunStore,
    private val patches: PatchService,
    private val json: ObjectMapper,
) {
    @GetMapping("/runs/{runId}/sbom.cdx.json")
    fun sbom(@PathVariable runId: String): ResponseEntity<JsonNode> = ResponseEntity.ok()
        .contentType(MediaType.parseMediaType("application/vnd.cyclonedx+json"))
        .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename("sbom.cdx.json").build().toString())
        .body(CycloneDx(json).build(history.get(runId)))

    @GetMapping("/runs/{runId}/findings/{findingId}/patch")
    fun patch(
        @PathVariable runId: String,
        @PathVariable findingId: String,
        @RequestParam(required = false, defaultValue = "false") masked: Boolean,
        request: HttpServletRequest,
    ): ResponseEntity<String> {
        val report = history.get(runId).report ?: throw MissingResource()
        val finding = findingsOf(report).firstOrNull {
            it.path("id").asText() == findingId || it.path("fingerprint").asText() == findingId
        } ?: throw MissingResource()
        val category = finding.path("category").asText()
        if (category != "SCA" && category != "SECRET") throw NoAutofix(NO_AUTOFIX_MESSAGE)
        val entry = patches.load(runId, finding.path("id").asText())
            ?: throw Gone("Снимок проекта этого запуска больше недоступен: патч не построить. Запустите проверку заново.")
        if (entry.path("status").asText() != "READY") {
            throw Conflict(entry.path("message").asText("Патч для этой находки не поддерживается."))
        }
        if (category == "SECRET" && !masked && !loopback(request.remoteAddr)) {
            return ResponseEntity.status(403).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body("""{"code":"FORBIDDEN","message":"Патч секрета содержит исходную строку и отдаётся только с локального адреса."}""")
        }
        val name = "fix-" + finding.path("id").asText().takeLast(8) + ".patch"
        val disposition = if (masked) ContentDisposition.inline() else ContentDisposition.attachment()
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .contentType(MediaType.parseMediaType("text/x-diff;charset=UTF-8"))
            .header(HttpHeaders.CONTENT_DISPOSITION, disposition.filename(name).build().toString())
            .body(entry.path(if (masked) "preview" else "diff").asText())
    }

    private fun loopback(address: String?): Boolean =
        address != null && runCatching { InetAddress.getByName(address).isLoopbackAddress }.getOrDefault(false)
}
