package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.*
import workflow.nodes.InputRejected
import workflow.nodes.RepositoryAllowlist
import workflow.nodes.UNSUPPORTED_REPOSITORY
import workflow.nodes.normalizeRepositoryInput
import workflow.nodes.validRepositoryUrl

data class RepositorySettings(val repositories: List<String>)

@Service
class RepositorySettingsStore(
    private val db: JdbcTemplate,
    private val json: ObjectMapper,
    private val demo: DemoMode,
    @Value("\${ALLOWED_REPOS:https://github.com/example-org/training}") allowed: String,
) : RepositoryAllowlist {
    private val defaults = allowed.split(',').map(String::trim).filter(::validRepositoryUrl).distinct()

    override fun urls(): List<String> =
        if (demo.enabled && demo.repositories.isNotEmpty()) demo.repositories else db.query("SELECT payload FROM repository_settings WHERE id = 1") { row, _ ->
            json.readValue(row.getString(1), RepositorySettings::class.java).repositories
        }.singleOrNull() ?: defaults

    @Synchronized
    fun replace(request: JsonNode): RepositorySettings {
        val urls = request.path("repositories")
        if (!urls.isArray || urls.size() > 100 || urls.any { !it.isTextual || canonical(it.asText()) == null }) {
            throw InputRejected(UNSUPPORTED_REPOSITORY)
        }
        return save(urls.mapNotNull { canonical(it.asText()) }.distinct())
    }

    /** Принимает `/`, `.git` и `/tree/<ветка>` на конце, хранит канонический https://github.com/owner/repo. */
    private fun canonical(raw: String): String? = normalizeRepositoryInput(raw)?.url?.takeIf(::validRepositoryUrl)

    @Synchronized
    fun add(request: JsonNode): RepositorySettings {
        approve(request.path("url").textValue() ?: "")
        return RepositorySettings(urls())
    }

    /**
     * Явное действие пользователя (проект, сценарий, запуск) подключает репозиторий: ссылка нормализуется и
     * добавляется в список. Транспортные проверки (https, известный хост, публичный IP, без редиректов) остаются.
     */
    @Synchronized
    fun approve(raw: String): String {
        val url = canonical(raw) ?: throw InputRejected(UNSUPPORTED_REPOSITORY)
        val current = urls()
        if (demo.enabled) {
            // Публичный демо-режим: произвольные ссылки из интернета не подключаются.
            if (url !in current) throw InputRejected("В демо-режиме доступны только подготовленные репозитории")
            return url
        }
        if (url in current) return url
        if (current.size >= 100) throw InputRejected("В списке может быть не более 100 репозиториев")
        save(current + url)
        return url
    }

    /** Подключает все адреса `source.repo` сценария, введённые пользователем. */
    fun approveGraph(workflow: workflow.engine.Workflow) {
        workflow.nodes.filter { it.type == "source.repo" }
            .mapNotNull { it.params.path("url").textValue()?.takeIf(String::isNotBlank) }
            .forEach(::approve)
    }

    private fun save(urls: List<String>): RepositorySettings {
        val settings = RepositorySettings(urls)
        db.update("MERGE INTO repository_settings (id, payload) KEY(id) VALUES (1, ?)", json.writeValueAsString(settings))
        return settings
    }
}

@RestController
@RequestMapping("/api/settings/repositories")
class RepositorySettingsController(private val store: RepositorySettingsStore) {
    @GetMapping fun get() = RepositorySettings(store.urls())

    @PutMapping(consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun put(@RequestBody request: JsonNode) = store.replace(request)

    @PostMapping(consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun post(@RequestBody request: JsonNode) = store.add(request)
}
