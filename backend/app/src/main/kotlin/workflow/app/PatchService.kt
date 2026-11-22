package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import workflow.nodes.findingsOf
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * Готовые патчи строятся при завершении запуска, пока снимок проекта ещё на диске (рабочая папка потом удаляется),
 * и лежат в `<data>/patches/<runId>.json`. Патчи секретов содержат исходную строку: файлы хранятся только локально.
 */
@Service
class PatchService(
    private val json: ObjectMapper,
    @Value("\${workflow.data-dir:data}") private val data: String,
) {
    fun capture(runId: String, report: JsonNode, project: Path?) {
        if (project == null || !runId.matches(idPattern)) return
        val root = runCatching { project.toRealPath() }.getOrNull() ?: return
        val read = { relative: String -> readSnapshotFile(root, relative) }
        val entries = json.createObjectNode()
        for (finding in findingsOf(report)) {
            val id = finding.path("id").textValue() ?: continue
            val entry = when (val outcome = FindingPatches.create(finding, read)) {
                is PatchOutcome.Ready -> json.createObjectNode().put("status", "READY")
                    .put("diff", outcome.diff).put("preview", outcome.preview)
                is PatchOutcome.Unsupported -> json.createObjectNode().put("status", "UNSUPPORTED").put("message", outcome.message)
                is PatchOutcome.NoAutofix -> continue
            }
            entries.set<JsonNode>(id, entry)
        }
        val directory = Files.createDirectories(Path.of(data).toAbsolutePath().resolve("patches"))
        Files.writeString(directory.resolve("$runId.json"), json.writeValueAsString(entries))
    }

    /** Запись о патче находки; null, если патчей запуска нет (снимок был недоступен). */
    fun load(runId: String, findingId: String): JsonNode? {
        if (!runId.matches(idPattern)) return null
        val file = Path.of(data).toAbsolutePath().resolve("patches/$runId.json")
        if (!Files.isRegularFile(file)) return null
        return runCatching { json.readTree(Files.readString(file)) }.getOrNull()?.get(findingId)?.takeIf { it.isObject }
    }

    companion object {
        private val idPattern = Regex("[A-Za-z0-9-]{1,64}")
        private const val MAX_FILE_BYTES = 2L * 1024 * 1024

        internal fun readSnapshotFile(root: Path, relative: String): String? {
            if (relative.isEmpty() || relative.startsWith("/") || relative.contains('\\')) return null
            val file = root.resolve(relative).normalize()
            if (!file.startsWith(root) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) return null
            if (Files.size(file) > MAX_FILE_BYTES) return null
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            return try {
                decoder.decode(java.nio.ByteBuffer.wrap(Files.readAllBytes(file))).toString().removePrefix("﻿")
            } catch (_: CharacterCodingException) {
                null
            }
        }
    }
}
