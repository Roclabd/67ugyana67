package workflow.app

import workflow.engine.PRODUCT_NAME

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import workflow.nodes.findingsOf
import java.net.URLEncoder
import java.time.Instant
import java.util.UUID

/**
 * SBOM CycloneDX 1.5 по результату SCA: уязвимые зависимости из находок плюс проверенные и чистые
 * (из `coverage.dismissed` ноды SCA). Зависимости без записей в справочнике анализатор не перечисляет, поэтому их нет и здесь.
 */
class CycloneDx(private val json: ObjectMapper) {
    private data class Component(val group: String, val name: String, val version: String) {
        val purl get() = "pkg:maven/${enc(group)}/${enc(name)}@${enc(version)}"
        val valid get() = group.isNotEmpty() && name.isNotEmpty() && version.isNotEmpty()
    }

    fun build(run: RunRecord, now: Instant = Instant.now()): ObjectNode {
        val findings = run.report?.let(::findingsOf).orEmpty().filter { it.path("category").asText() == "SCA" }
        val components = linkedSetOf<Component>()
        for (finding in findings) {
            components += Component(finding.path("group").asText(), finding.path("artifact").asText(), finding.path("version").asText())
        }
        run.nodeRuns.flatMap { it.coverage?.path("dismissed")?.toList().orEmpty() }
            .filter { it.path("rule").asText() == "sca.maven-advisory" }
            .mapNotNull { dismissedPattern.find(it.path("reason").asText()) }
            .forEach { components += Component(it.groupValues[1], it.groupValues[2], it.groupValues[3]) }

        val root = json.createObjectNode()
        root.put("bomFormat", "CycloneDX").put("specVersion", "1.5")
        root.put("serialNumber", "urn:uuid:" + UUID.nameUUIDFromBytes(("codeguard-sbom:" + run.id).toByteArray()))
        root.put("version", 1)
        val metadata = root.putObject("metadata")
        metadata.put("timestamp", (run.finishedAt ?: now).toString())
        metadata.putObject("tools").putArray("components").addObject()
            .put("type", "application").put("name", PRODUCT_NAME)
        metadata.putObject("component").put("type", "application").put("bom-ref", "scanned-project")
            .put("name", projectName(run))
        metadata.putArray("properties").addObject().put("name", "codeguard:scope")
            .put("value", "Зависимости, найденные SCA в справочнике уязвимостей (уязвимые и проверенные чистые); " +
                "зависимости без записей в справочнике не перечисляются.")

        val array = root.putArray("components")
        for (component in components.filter { it.valid }.sortedWith(compareBy({ it.group }, { it.name }, { it.version }))) {
            array.addObject().put("type", "library").put("bom-ref", component.purl)
                .put("group", component.group).put("name", component.name).put("version", component.version)
                .put("purl", component.purl)
        }
        val vulnerabilities = root.putArray("vulnerabilities")
        for (finding in findings.sortedBy { it.path("advisoryId").asText() }) {
            val component = Component(finding.path("group").asText(), finding.path("artifact").asText(), finding.path("version").asText())
            val id = finding.path("advisoryId").asText()
            if (id.isEmpty() || !component.valid) continue
            val entry = vulnerabilities.addObject().put("id", id)
            val source = if (id.startsWith("CVE-")) "NVD" to "https://nvd.nist.gov/vuln/detail/$id"
            else "GitHub Advisory Database" to "https://github.com/advisories/$id"
            entry.putObject("source").put("name", source.first).put("url", source.second)
            val rating = entry.putArray("ratings").addObject()
            rating.putObject("source").put("name", PRODUCT_NAME)
            rating.put("severity", severity(finding.path("severity").asText()))
            finding.path("description").textValue()?.let { entry.put("description", it) }
            finding.path("remediation").textValue()?.let { entry.put("recommendation", it) }
            entry.putArray("affects").addObject().put("ref", component.purl)
        }
        return root
    }

    private fun projectName(run: RunRecord): String =
        run.trigger.path("source").path("url").textValue()?.trimEnd('/')?.substringAfterLast('/')?.removeSuffix(".git")
            ?.takeIf(String::isNotBlank) ?: run.workflowName ?: "scanned-project"

    private fun severity(value: String) = when (value) {
        "CRITICAL" -> "critical"
        "HIGH" -> "high"
        "MEDIUM" -> "medium"
        "LOW" -> "low"
        else -> "info"
    }

    companion object {
        private val dismissedPattern = Regex("Версия ([^:\\s]+):([^:\\s]+):(\\S+) вне уязвимых")
        private fun enc(value: String) = URLEncoder.encode(value, Charsets.UTF_8).replace("+", "%20")
    }
}
