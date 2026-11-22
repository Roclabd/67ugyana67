package workflow.analyzers.report

import codeguard.analyzers.model.Endpoint
import codeguard.analyzers.model.SecurityRule
import codeguard.analyzers.model.SpringModel

internal data class RoutePolicy(
    val status: String,
    val rule: SecurityRule?,
    val subsequent: List<SecurityRule>,
)

private val unresolved = RoutePolicy("unresolved", null, emptyList())
private val pathMatchers = setOf("requestMatchers", "antMatchers", "mvcMatchers", "authorize")

internal fun routePolicy(model: SpringModel, endpoint: Endpoint): RoutePolicy {
    val route = endpoint.path?.let(::segments) ?: return unresolved
    if (route.any { !literalSegment(it) && !variableSegment(it) }) return unresolved

    val rules = model.securityRules
    val chain = rules.firstOrNull()?.chain ?: return unresolved
    if (rules.any { it.chain != chain }) return unresolved
    if (model.ignoredPaths.any { pathMatch(it.value, route) != Match.NO }) return unresolved

    var first: SecurityRule? = null
    val subsequent = mutableListOf<SecurityRule>()
    for (rule in rules) {
        when (ruleMatch(rule, endpoint.method, route)) {
            Match.NO -> Unit
            Match.UNKNOWN -> if (first == null) return unresolved
            Match.YES -> if (first == null) first = rule else subsequent.add(rule)
        }
    }
    return first?.let { RoutePolicy("matched", it, subsequent) } ?: unresolved
}

private enum class Match { YES, NO, UNKNOWN }

private fun ruleMatch(rule: SecurityRule, method: String?, route: List<String>): Match {
    if (rule.method != null && method != null && rule.method != method) return Match.NO
    if (rule.hasUnresolvedPatterns) return Match.UNKNOWN
    val paths = when {
        rule.matcher == "anyRequest" -> Match.YES
        rule.matcher !in pathMatchers || rule.patterns.isEmpty() -> Match.UNKNOWN
        else -> {
            var result = Match.NO
            for (pattern in rule.patterns) {
                when (pathMatch(pattern, route)) {
                    Match.YES -> {
                        result = Match.YES
                        break
                    }
                    Match.UNKNOWN -> result = Match.UNKNOWN
                    Match.NO -> Unit
                }
            }
            result
        }
    }

    return if (paths == Match.YES && rule.method != null && method == null) Match.UNKNOWN else paths
}

// Compare declared segments directly. A literal at a route variable is only a possible match.
private fun pathMatch(pattern: String, route: List<String>): Match {
    val patternSegments = segments(pattern) ?: return Match.UNKNOWN
    val prefixMatch = patternSegments.lastOrNull() == "**"
    val prefix = if (prefixMatch) patternSegments.dropLast(1) else patternSegments
    if (prefix.any { it != "*" && !variableSegment(it) && !literalSegment(it) }) return Match.UNKNOWN
    if (route.size < prefix.size || (!prefixMatch && route.size != prefix.size)) return Match.NO

    var result = Match.YES
    for ((index, segment) in prefix.withIndex()) {
        val routeSegment = route[index]
        if (segment == "*" || variableSegment(segment) || segment == routeSegment) continue
        if (!variableSegment(routeSegment)) return Match.NO
        result = Match.UNKNOWN
    }
    return result
}

private fun segments(path: String): List<String>? {
    if (!path.startsWith('/') || path.length > 4096) return null
    if (path == "/") return emptyList()
    return path.substring(1).split('/').takeIf { parts -> parts.none(String::isEmpty) }
}

private fun literalSegment(value: String): Boolean = value.isNotEmpty() && value != "." && value != ".." &&
    value.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "-._~" }

private fun variableSegment(value: String): Boolean = value.length > 2 && value.first() == '{' && value.last() == '}' &&
    value.substring(1, value.lastIndex).all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' }
