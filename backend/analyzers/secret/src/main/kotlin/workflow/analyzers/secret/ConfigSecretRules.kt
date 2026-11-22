package workflow.analyzers.secret

import codeguard.analyzers.model.ConfigKind
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.isVersionCatalog

private val environmentListEntry = Regex("""(?:^|\.)environment\[\d+\]$""")
private val environmentName = Regex("""[A-Za-z_][A-Za-z0-9_.-]*""")
private val bearerValue = Regex("""Bearer\s+(.*)""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
private val bracedReference = Regex("""(?<!\$)\$\{""")
private val bareReference = Regex("""(?<!\$)\$[A-Za-z_][A-Za-z0-9_]*""")
private val springDefault = Regex("""\$\{([A-Za-z_][A-Za-z0-9_.-]*):(.*)}""", RegexOption.DOT_MATCHES_ALL)
private val shellDefault = Regex("""\$\{([A-Za-z_][A-Za-z0-9_]*):?-(.*)}""", RegexOption.DOT_MATCHES_ALL)
private val nonDefaultExpansion = Regex("""\$\{[A-Za-z_][A-Za-z0-9_]*:?[?+=].*}""", RegexOption.DOT_MATCHES_ALL)
private val artifactVersion = Regex("""[vV]?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.+-]+)?""")

internal fun scanConfigSecrets(model: ProjectModel): SecretRuleResult {
    val candidates = mutableListOf<SecretCandidate>()
    val dismissed = mutableListOf<SecretDismissal>()

    for (entry in model.config) {
        var key = entry.key
        var value = entry.value.trim()
        var inheritedEnvironment = false
        val environmentList = environmentListEntry.containsMatchIn(key)
        if (environmentList) {
            val assignment = value.indexOf('=')
            key = value.substringBefore('=').trim()
            if (!environmentName.matches(key)) continue
            inheritedEnvironment = assignment < 0
            value = if (inheritedEnvironment) "" else value.substring(assignment + 1).trim()
        }

        val bearer = bearerValue.matchEntire(value)
        val embedded = embeddedCredential(value)
        val named = if (bearer != null) "configuration-token" else secretKind(key)
        val shape = if (embedded == null && named == null) knownTokenShape(value) else null
        val kind = embedded?.first ?: named ?: shape?.first ?: continue
        val credential = embedded?.second ?: shape?.second ?: bearer?.groupValues?.get(1)?.trim() ?: value
        val path = entry.path
        if (embedded == null && shape == null && isStatusWord(credential)) continue
        if (isVersionCatalog(path) && artifactVersion.matches(credential)) continue
        val dotenv = path.substringAfterLast('/').let {
            it == ".env" || it.startsWith(".env.") || it.endsWith(".env") ||
                it.equals("Dockerfile", true) || it.startsWith("Dockerfile.", true) || it.endsWith(".dockerfile", true)
        }
        val shellExpansion = dotenv || environmentList || key.startsWith("environment.") || ".environment." in key
        // The parser preserves single-quoted dotenv values as literal strings.
        val interpolation = !dotenv || entry.kind != ConfigKind.LITERAL || !value.startsWith("${'$'}{")
        val expansion = if (shellExpansion) shellDefault.matchEntire(credential) else null
        val fallback = if (!interpolation || shellExpansion && nonDefaultExpansion.matches(credential)) null
            else expansion ?: springDefault.matchEntire(credential)

        val rule = if (fallback != null) "secret-fallback" else kind
        val secret = fallback?.groupValues?.get(2)?.trim() ?: credential
        val reason = when {
            inheritedEnvironment || entry.kind == ConfigKind.ENV -> "environment-reference"
            interpolation && (bracedReference.containsMatchIn(secret) || bareReference.matches(secret) ||
                shellExpansion && bareReference.containsMatchIn(secret)) ->
                if (fallback != null) "non-literal-fallback" else "environment-reference"
            secret.isEmpty() || isPlaceholder(secret) -> "placeholder"
            else -> null
        }

        if (reason != null) dismissed.add(SecretDismissal(rule, entry.location, reason))
        else candidates.add(SecretCandidate(rule, secret, entry.location))
    }

    return SecretRuleResult(candidates, dismissed)
}

private val statusWords = setOf(
    "COMPLETE", "COMPLETED", "PARTIAL", "FAILED", "SUCCESS", "ENABLED", "DISABLED", "TRUE", "FALSE",
    "NONE", "NULL", "REQUIRED", "OPTIONAL", "N/A",
)

/** Статус/enum-слово (COMPLETE, required) — не секрет; в JSON так же простое слово без цифр. */
private fun isStatusWord(value: String): Boolean = value.uppercase() in statusWords
