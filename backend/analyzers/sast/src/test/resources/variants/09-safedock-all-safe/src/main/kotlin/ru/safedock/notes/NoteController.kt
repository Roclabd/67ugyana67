package ru.safedock.notes

import java.security.Principal
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/notes")
class NoteController(
    private val jdbc: JdbcTemplate,
    private val named: NamedParameterJdbcTemplate,
    private val service: NoteService,
) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long, principal: Principal): Map<String, Any?> =
        jdbc.queryForMap("SELECT note_id, title FROM note WHERE note_id = ? AND owner_id = ?", id, principal.name)

    @GetMapping("/search")
    fun search(@RequestParam title: String, principal: Principal): List<Map<String, Any?>> =
        named.queryForList(
            "SELECT note_id, title FROM note WHERE title LIKE :title AND owner_id = :owner",
            MapSqlParameterSource("title", "%$title%").addValue("owner", principal.name),
        )

    @GetMapping("/by-title")
    fun byTitle(@RequestParam title: String, principal: Principal): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT note_id, title FROM note WHERE title = ? AND owner_id = ?", title, principal.name)

    @GetMapping("/{id}/checked")
    fun checked(@PathVariable id: Long): NoteEntity = service.loadChecked(id)

    @GetMapping("/tag")
    fun tag(@RequestParam tag: String): List<NoteEntity> = service.byTag(tag)

    @GetMapping("/older/{days}")
    fun older(@PathVariable days: Int, principal: Principal): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT note_id, title FROM note WHERE age_days > $days AND owner_id = ?", principal.name)
}
