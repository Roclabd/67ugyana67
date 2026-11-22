package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceType

private val credentialUrl = Regex("""(?i)^(?:jdbc:)?[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/?#]+)@[^\s:/?#]+""")
private val variableReference = Regex("""\$(?:\{[^}]+}|[A-Za-z_]\w*)""")

internal fun urlPassword(value: String): String? =
    credentialUrl.find(value)?.groupValues?.get(1)
        ?.takeUnless { isPlaceholder(it) || variableReference.containsMatchIn(it) }

private val privateKeyStart = Regex("""^-----BEGIN ((?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----$""")
private val base64Line = Regex("""[A-Za-z0-9+/]+={0,2}""")
private val looseKeyBody = Regex("""[A-Za-z0-9+/_.=-]{8,}""")
private val keyPlaceholder = Regex("""(?i)your|example|placeholder|redacted|xxx|\.\.\.|changeme|replace""")

internal fun scanPemFiles(model: ProjectModel): List<SecretCandidate> = buildList {
    for (file in model.files.filter { it.type == SourceType.PEM }) {
        var marker: String? = null
        var startLine = 0
        val body = StringBuilder()
        file.text.lineSequence().forEachIndexed { index, rawLine ->
            val line = rawLine.trim()
            val begin = privateKeyStart.matchEntire(line)
            when {
                begin != null -> {
                    marker = begin.groupValues[1]
                    startLine = index + 1
                    body.clear()
                }
                marker == null -> Unit
                line == "-----END $marker-----" -> {
                    if (body.length >= 16) {
                        add(SecretCandidate("configuration-token", body.toString(), Location(file.path, startLine)))
                    }
                    marker = null
                    body.clear()
                }
                base64Line.matches(line) -> body.append(line)
                // Fake or test key bodies ("FAKE-TRAINING-MARKER") are not base64, but a private-key block is still a leaked key file.
                looseKeyBody.matches(line) && !keyPlaceholder.containsMatchIn(line) -> body.append(line)
                else -> {
                    marker = null
                    body.clear()
                }
            }
        }
    }
}

private val urlParameter = Regex("""(?i)[?&;]([a-z][a-z0-9_.-]{1,40})=([^&;\s#"']+)""")

/** Secret passed as a query or connection-string parameter: `?password=x`, `;pwd=x`, `&access_token=x`. */
internal fun urlParameterCredential(value: String): Pair<String, String>? {
    if (!value.contains('=')) return null
    for (match in urlParameter.findAll(value)) {
        val kind = secretKind(match.groupValues[1]) ?: continue
        val secret = match.groupValues[2]
        if (isPlaceholder(secret) || variableReference.containsMatchIn(secret) || secret.contains("{{")) continue
        return kind to secret
    }
    return null
}

private val tokenShapes = listOf(
    "api-key" to Regex("""\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"""),
    "api-key" to Regex("""\bgh[pousr]_[0-9A-Za-z]{36,}\b"""),
    "api-key" to Regex("""\bgithub_pat_[0-9A-Za-z_]{40,}\b"""),
    "api-key" to Regex("""\bxox[baprs]-[0-9A-Za-z-]{10,}"""),
    "configuration-token" to Regex("""\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b"""),
    "api-key" to Regex("""\b[sr]k_live_[0-9A-Za-z]{16,}"""),
    "api-key" to Regex("""\bAIza[0-9A-Za-z_-]{35}\b"""),
)
private val basicLiteral = Regex("""^Basic\s+([A-Za-z0-9+/]{8,}={0,2})$""")

/** Well-known credential formats recognised by their shape, independent of the name they are stored under. */
internal fun knownTokenShape(value: String): Pair<String, String>? {
    for ((kind, regex) in tokenShapes) {
        regex.find(value)?.let { return kind to it.value }
    }
    return null
}

/** `Basic <base64(user:pass)>` literal with a real password. */
internal fun basicAuthPassword(value: String): String? {
    val encoded = basicLiteral.matchEntire(value.trim())?.groupValues?.get(1) ?: return null
    val decoded = try {
        java.util.Base64.getDecoder().decode(encoded).decodeToString(throwOnInvalidSequence = true)
    } catch (_: IllegalArgumentException) {
        return null
    } catch (_: java.nio.charset.CharacterCodingException) {
        return null
    }
    val password = decoded.substringAfter(':', "").takeIf { ':' in decoded && decoded.substringBefore(':').isNotEmpty() } ?: return null
    return password.takeUnless { isPlaceholder(it) || variableReference.containsMatchIn(it) }
}

/** Credential embedded in a literal: URL userinfo, URL parameter, Basic header or known token shape. */
internal fun embeddedCredential(value: String): Pair<String, String>? =
    urlPassword(value)?.let { "password" to it }
        ?: urlParameterCredential(value)
        ?: basicAuthPassword(value)?.let { "password" to it }
