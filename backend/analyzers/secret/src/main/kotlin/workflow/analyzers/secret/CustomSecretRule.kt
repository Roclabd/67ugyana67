package workflow.analyzers.secret

import com.google.re2j.Pattern
import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import java.util.concurrent.TimeUnit

internal const val MAX_CUSTOM_SECRET_PATTERN_LENGTH = 1024
private const val MAX_LINE_LENGTH = 16_384
private const val MAX_CANDIDATES = 1_000
private val scanBudgetNanos = TimeUnit.SECONDS.toNanos(1)

internal data class CustomSecretResult(val candidates: List<SecretCandidate>, val incomplete: Boolean)

/** Applies the expression to individual source lines and returns partial findings if a limit is reached. */
internal fun scanCustomSecrets(model: ProjectModel, pattern: Pattern): CustomSecretResult {
    if (pattern.pattern().length > MAX_CUSTOM_SECRET_PATTERN_LENGTH) {
        return CustomSecretResult(emptyList(), incomplete = true)
    }

    val started = System.nanoTime()
    val candidates = mutableListOf<SecretCandidate>()
    var incomplete = false
    fun expired() = Thread.currentThread().isInterrupted || System.nanoTime() - started >= scanBudgetNanos

    for (file in model.files) {
        if (expired()) return CustomSecretResult(candidates, incomplete = true)
        if (!file.isCustomSecretSource() || isCustomSecretScanExcluded(file.path)) continue
        val source = file.text
        var start = 0
        var line = 1
        while (start < source.length) {
            if (expired()) return CustomSecretResult(candidates, incomplete = true)
            var end = start
            while (end < source.length && source[end] != '\n' && source[end] != '\r') {
                end++
                if ((end - start) % MAX_LINE_LENGTH == 0 && expired()) {
                    return CustomSecretResult(candidates, incomplete = true)
                }
            }

            if (end - start > MAX_LINE_LENGTH) {
                // Keep anchors and boundaries meaningful by skipping the entire line.
                incomplete = true
            } else {
                val matcher = pattern.matcher(source.substring(start, end))
                while (true) {
                    if (expired()) return CustomSecretResult(candidates, incomplete = true)
                    if (!matcher.find()) break
                    if (matcher.start() == matcher.end()) continue
                    if (candidates.size == MAX_CANDIDATES) return CustomSecretResult(candidates, incomplete = true)
                    candidates += SecretCandidate("custom-regex", matcher.group(), Location(file.path, line))
                }
                if (expired()) return CustomSecretResult(candidates, incomplete = true)
            }

            start = if (source.getOrNull(end) == '\r' && source.getOrNull(end + 1) == '\n') end + 2 else end + 1
            line++
        }
    }
    return CustomSecretResult(candidates, incomplete)
}
