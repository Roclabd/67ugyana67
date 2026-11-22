package ru.codeguard.ai

import ru.codeguard.ai.context.CodeContext
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.ai.model.AiLocation
import ru.codeguard.ai.prompt.Prompts
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Инвариант: значение секрета (и его Base64-формы) не попадает в запрос к LLM ни прямо, ни через фрагмент рядом с находкой SAST. */
class SecretLeakInvariantTest {
    private val raw = "S3cr3t-Value-123"
    private val forms = listOf(
        raw,
        Base64.getEncoder().encodeToString(raw.toByteArray()),
        Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray()),
        "user:$raw",
        Base64.getEncoder().encodeToString("user:$raw".toByteArray()),
    )

    private val clientSource = listOf(
        "package app",
        "",
        "class Client(private val jdbc: JdbcTemplate) {",
        "    val password = \"$raw\"",
        "    val blob = \"${forms[1]}\"",
        "    val basic = \"${forms[4]}\"",
        "    fun find(tag: String) = jdbc.queryForList(\"SELECT code FROM t WHERE tag = '\$tag'\")",
        "}",
    ).joinToString("\n")

    private val settingsSource = listOf(
        "package app",
        "object Settings {",
        "    const val X = \"$raw\"",
        "    fun query(tag: String) = \"SELECT * FROM t WHERE tag = '\$tag'\"",
        "}",
    ).joinToString("\n")

    private fun sast(id: String, path: String, line: Int) =
        AiFinding(id, "SAST", "sql-injection", "HIGH", path, line, title = "SQL-инъекция", description = "Конкатенация в запросе")

    private fun payload(findings: List<AiFinding>): String {
        val sources = mapOf("src/Client.kt" to clientSource, "src/Settings.kt" to settingsSource)
        val context = CodeContext({ path -> sources[path] }).apply { registerSecrets(findings) }
        return Prompts.explainMessages(findings, context).joinToString("\n") { it.content }
    }

    @Test
    fun snippetNearSastFindingDoesNotContainSecretValues() {
        val text = payload(listOf(sast("s1", "src/Client.kt", 7)))
        for (form in forms) assertFalse(form in text, "leak: $form")
        assertTrue("SELECT code FROM t" in text, "the SAST context stays useful")
    }

    @Test
    fun secretFindingLinesAreHiddenEvenForNeutralNames() {
        val secret = AiFinding(
            "k1", "SECRET", "password", "HIGH", "src/Settings.kt", 3,
            evidence = listOf(AiLocation("src/Client.kt", 7)), secretMasked = "****",
        )
        val text = payload(listOf(secret, sast("s2", "src/Settings.kt", 4)))
        for (form in forms) assertFalse(form in text, "leak: $form")
        assertTrue("SELECT * FROM t" in text)
    }
}
