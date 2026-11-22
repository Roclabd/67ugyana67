package workflow.app

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.springframework.beans.factory.annotation.Value
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import workflow.engine.*
import java.security.SecureRandom
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class MissingResource : RuntimeException()
class Conflict(message: String) : RuntimeException(message)

@Component
class SecretBox(@Value("\${APP_SECRETS_KEY:}") encodedKey: String) {
    private val random = SecureRandom()
    private val key = encodedKey.takeIf(String::isNotBlank)?.let {
        SecretKeySpec(Base64.getDecoder().decode(it).also { bytes ->
            require(bytes.size == 32) { "APP_SECRETS_KEY должен содержать 32 байта в Base64" }
        }, "AES")
    }

    fun seal(value: String, owner: String): String {
        val nonce = ByteArray(12).also(random::nextBytes)
        val cipher = cipher(Cipher.ENCRYPT_MODE, nonce, owner)
        return Base64.getEncoder().encodeToString(nonce + cipher.doFinal(value.toByteArray(Charsets.UTF_8)))
    }

    fun open(value: String, owner: String): String {
        val bytes = Base64.getDecoder().decode(value)
        val cipher = cipher(Cipher.DECRYPT_MODE, bytes.copyOfRange(0, 12), owner)
        return cipher.doFinal(bytes.copyOfRange(12, bytes.size)).toString(Charsets.UTF_8)
    }

    private fun cipher(mode: Int, nonce: ByteArray, owner: String): Cipher {
        val secret = key ?: throw Conflict("Для сохранения секретов задайте APP_SECRETS_KEY")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, secret, GCMParameterSpec(128, nonce))
            updateAAD(owner.toByteArray(Charsets.UTF_8))
        }
    }
}

data class WorkflowSummary(val id: String, val name: String, val version: Long, val updatedAt: Instant)

@Service
class WorkflowStore(
    private val db: JdbcTemplate,
    private val json: ObjectMapper,
    private val nodes: NodeRegistry,
    private val validator: GraphValidator,
    private val secrets: SecretBox,
) {
    fun list(): List<WorkflowSummary> = db.query(
        "SELECT id, name, version, updated_at FROM workflows ORDER BY updated_at DESC, id",
    ) { row, _ -> WorkflowSummary(row.getString("id"), row.getString("name"), row.getLong("version"),
        row.getObject("updated_at", OffsetDateTime::class.java).toInstant()) }

    fun get(id: String): Workflow = mask(read(id))

    fun unlocked(id: String): Workflow = transformSecrets(read(id)) { owner, value -> secrets.open(value, owner) }

    fun mask(workflow: Workflow): Workflow = transformSecrets(workflow) { _, _ -> Redaction.MASK }

    fun withoutSecrets(workflow: Workflow): Workflow = workflow.copy(nodes = workflow.nodes.map { node ->
        val params = node.params.deepCopy<ObjectNode>()
        nodes[node.type]?.secretParams.orEmpty().forEach { params.remove(it) }
        node.copy(params = params)
    })

    fun secretValues(workflow: Workflow): List<String> = workflow.nodes.flatMap { node ->
        nodes[node.type]?.secretParams.orEmpty().mapNotNull { node.params[it]?.textValue() }
    }

    fun create(value: Workflow): Workflow {
        value.project?.let(::requireProject)
        val workflow = value.copy(id = UUID.randomUUID().toString(), version = 1)
        val stored = encrypt(workflow, null)
        db.update("INSERT INTO workflows(id, name, version, updated_at, payload) VALUES (?, ?, ?, ?, ?)",
            workflow.id, workflow.name, workflow.version, now(), json.writeValueAsString(stored))
        return mask(stored)
    }

    @Transactional
    fun update(id: String, value: Workflow): Workflow {
        val previous = read(id, lock = true)
        if (value.version != 0L && value.version != previous.version) throw Conflict("Версия сценария изменилась")
        value.project?.let(::requireProject)
        val workflow = value.copy(id = id, version = previous.version + 1, project = value.project ?: previous.project)
        val stored = encrypt(workflow, previous)
        db.update("UPDATE workflows SET name = ?, version = ?, updated_at = ?, payload = ? WHERE id = ?",
            workflow.name, workflow.version, now(), json.writeValueAsString(stored), id)
        return mask(stored)
    }

    fun delete(id: String) {
        if (db.update("DELETE FROM workflows WHERE id = ?", id) == 0) throw MissingResource()
    }

    private fun read(id: String, lock: Boolean = false): Workflow {
        val sql = "SELECT payload FROM workflows WHERE id = ?" + if (lock) " FOR UPDATE" else ""
        return db.query(sql, { row, _ -> json.readValue(row.getString(1), Workflow::class.java) }, id)
            .singleOrNull() ?: throw MissingResource()
    }

    private fun encrypt(workflow: Workflow, previous: Workflow?): Workflow {
        val old = previous?.nodes?.associateBy { it.id }.orEmpty()
        val restored = workflow.copy(nodes = workflow.nodes.map { node ->
            if (!node.params.isObject) return@map node
            val params = node.params.deepCopy<ObjectNode>()
            for (field in nodes[node.type]?.secretParams.orEmpty()) {
                if (params[field]?.textValue() != Redaction.MASK) continue
                val ciphertext = old[node.id]?.takeIf { it.type == node.type }?.params?.get(field)?.textValue()
                    ?: throw InvalidGraph(listOf(GraphError("INVALID_SECRET", "Введите значение секретного параметра", node.id)))
                params.put(field, secrets.open(ciphertext, secretOwner(workflow, node, field)))
            }
            node.copy(params = params)
        })
        validator.requireValid(restored)
        return transformSecrets(restored) { owner, value -> secrets.seal(value, owner) }
    }

    private fun transformSecrets(workflow: Workflow, transform: (String, String) -> String): Workflow =
        workflow.copy(nodes = workflow.nodes.map { node ->
            val params = node.params.deepCopy<ObjectNode>()
            for (field in nodes[node.type]?.secretParams.orEmpty()) {
                val value = params[field]?.textValue() ?: continue
                params.put(field, transform(secretOwner(workflow, node, field), value))
            }
            node.copy(params = params)
        })

    private fun secretOwner(workflow: Workflow, node: WorkflowNode, field: String) =
        "${workflow.id}/${node.id}/${node.type}/$field"
}

internal fun now(): OffsetDateTime = OffsetDateTime.now(ZoneOffset.UTC)
