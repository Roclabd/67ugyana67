package ru.codeguard.ai.usefulness

import ru.codeguard.ai.context.Advisories
import ru.codeguard.ai.model.AiFinding
import ru.codeguard.sast.SastAnalyzer
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.rules.CredentialedCorsRule
import ru.codeguard.sast.rules.TlsVerificationRule

/**
 * Измеримая оценка полезности рекомендации (ТЗ: «оцените полезность рекомендаций»). Проверки детерминированные:
 *  - fixParses      — пример исправления разбирается Kotlin PSI без ошибок (для YAML — без литерала секрета);
 *  - sameIdentifier — в примере те же имена, что в исходном коде (исправление того места, а не абстрактный совет);
 *  - fixPattern     — признак правильного исправления для класса (SQL — плейсхолдеры без интерполяции, IDOR — владелец из Principal…);
 *  - rerunClean     — для TLS и CORS: наши правила SAST на примере исправления не находят ту же проблему;
 *  - targetSafe     — для SCA: рекомендованная версия вне всех уязвимых диапазонов справочника.
 */
class Usefulness(private val advisories: Advisories, private val source: (String) -> String?) {

    fun checks(f: AiFinding, fixExample: String?, recommendedVersion: String?): Map<String, Boolean> {
        if (f.category == "SCA") {
            val v = recommendedVersion ?: return mapOf("targetSafe" to false)
            return mapOf("targetSafe" to advisories.targetSafe(f.group, f.artifact, f.version, v), "fromFixedVersions" to (v in f.fixedVersions))
        }
        val fix = fixExample?.takeIf { it.isNotBlank() } ?: return mapOf("hasFixExample" to false)
        val out = linkedMapOf("hasFixExample" to true)
        val isConfig = f.path.endsWith(".yml") || f.path.endsWith(".yaml") || f.path.endsWith(".properties")
        out["fixParses"] = if (isConfig) configLooksValid(fix) else parsesAsKotlin(fix)
        sameIdentifier(f, fix)?.let { out["sameIdentifier"] = it }
        out["fixPattern"] = fixPattern(f, fix)
        rerunClean(f, fix)?.let { out["rerunClean"] = it }
        return out
    }

    // ───────────── Разбор ─────────────

    private fun parsesAsKotlin(code: String): Boolean {
        val stripped = code.trim().removePrefix("```kotlin").removePrefix("```kt").removePrefix("```").removeSuffix("```").trim()
        val asFile = stripped.contains(Regex("""(^|\n)\s*(@\w+.*\n\s*)*(class|object|interface|fun|import|package|@)\b"""))
        val candidates = if (asFile) listOf(stripped, wrapInFunction(stripped)) else listOf(wrapInFunction(stripped), wrapInClass(stripped))
        return candidates.any { SastProjectLoader.parseKotlin("Fix.kt", it).second.isEmpty() }
    }

    private fun wrapInFunction(code: String) = "fun __fix() {\n$code\n}\n"
    private fun wrapInClass(code: String) = "class __Fix {\n$code\n}\n"

    private fun configLooksValid(fix: String): Boolean =
        fix.lines().none { Regex("""^\s*\S+\s*:\s*["']?[A-Za-z0-9_\-]{12,}["']?\s*$""").matches(it) && !it.contains("\${") }

    // ───────────── Те же имена ─────────────

    private val keywords = setOf("fun", "val", "var", "return", "class", "object", "override", "private", "public", "internal", "String", "Long", "Int", "List", "Map", "true", "false", "null", "this", "apply", "listOf", "mapOf", "import", "package")

    /** null — исходного кода нет (файл недоступен), проверку не считаем. */
    private fun sameIdentifier(f: AiFinding, fix: String): Boolean? {
        val text = source(f.path) ?: return null
        val line = f.line ?: return null
        val lines = text.replace("\r\n", "\n").split('\n')
        // Строки находки и по 2 соседних: правильное исправление часто удаляет проблемную строку целиком
        // (TLS: убрать верификатор), но остаётся в том же месте кода.
        val original = ((line - 2).coerceAtLeast(1)..((f.endLine ?: line) + 2)).mapNotNull { lines.getOrNull(it - 1) }.joinToString(" ")
            .replace(Regex(""""(?:[^"\\]|\\.)*""""), " ") // имена — вне строковых литералов
        val ids = Regex("""\b[A-Za-z_][A-Za-z0-9_]{3,}\b""").findAll(original).map { it.value }.filter { it !in keywords }.toSet()
        if (ids.isEmpty()) return null
        return ids.any { Regex("""\b${Regex.escape(it)}\b""").containsMatchIn(fix) }
    }

    // ───────────── Признак правильного исправления ─────────────

    private fun fixPattern(f: AiFinding, fix: String): Boolean = when (f.findingClass) {
        "sql-injection" -> {
            val sqlLiterals = Regex(""""(?:[^"\\]|\\.)*"|""${'"'}[\s\S]*?""${'"'}""").findAll(fix).map { it.value }
                .filter { Regex("""(?i)\b(select|insert|update|delete|where)\b""").containsMatchIn(it) }.toList()
            sqlLiterals.isNotEmpty() && sqlLiterals.none { Regex("""\$\{?\w""").containsMatchIn(it) } &&
                sqlLiterals.any { it.contains('?') || Regex(""":\w+""").containsMatchIn(it) } && !fix.contains(Regex("""\+\s*\w+\s*\+\s*""""))
        }
        "credentialed-cors" -> !(Regex("""(?i)(allowedOrigin\w*|addAllowedOrigin\w*)\s*[=(]\s*(listOf\()?\s*"\*"""").containsMatchIn(fix) &&
            Regex("""(?i)allowCredentials\s*[=(]\s*true""").containsMatchIn(fix))
        "tls-verification" -> !Regex("""->\s*true\s*}""").containsMatchIn(fix) && !fix.contains("NoopHostnameVerifier") && !fix.contains("TrustAllStrategy") &&
            !Regex("""checkServerTrusted\([^)]*\)\s*\{\s*}""").containsMatchIn(fix)
        "route-authorization" -> Regex("""(?i)has(Any)?(Role|Authority)|authenticated\(\)|denyAll""").containsMatchIn(fix)
        // Владелец учитывается: условие по owner-колонке в запросе (уровень репозитория: «AND customer_id = ?»,
        // findByIdAndCustomerId) или личность пользователя вместе с owner-полем (уровень контроллера/сервиса).
        "object-authorization" -> {
            val owner = """(owner|customer|user|client|account)_?id"""
            val ownerInWhere = Regex("""(?is)\bwhere\b[^"]*\b$owner\s*=\s*[?:]""").containsMatchIn(fix) ||
                Regex("""(?i)find\w*By\w*And(Owner|Customer|User|Client|Account)""").containsMatchIn(fix)
            val identity = Regex("""(?i)Principal|Authentication|AuthenticationPrincipal|SecurityContextHolder""").containsMatchIn(fix) &&
                Regex("""(?i)$owner|ownerId|customerId|userId""").containsMatchIn(fix)
            ownerInWhere || identity
        }
        // SECRET: значение читается из окружения/конфигурации, литерала секрета нет
        "password", "api-key", "configuration-token", "secret-fallback", "recoverable-token" ->
            Regex("""(?i)getenv|@Value|\$\{|ConfigurationProperties|environment|vault|secretsManager""").containsMatchIn(fix) &&
                !Regex(""""[A-Za-z0-9_\-]{12,}"""").containsMatchIn(fix.replace(Regex("""\$\{[^}]*}"""), "")) &&
                !Regex("""\?:\s*"[^"]+"""").containsMatchIn(fix) && !Regex("""\$\{[^}:]+:[^}]+}""").containsMatchIn(fix)
        else -> fix.isNotBlank()
    }

    // ───────────── Перепроверка нашими правилами ─────────────

    /** Только для правил, которые работают на отдельном фрагменте (не требуют контекста эндпоинтов). */
    private fun rerunClean(f: AiFinding, fix: String): Boolean? {
        val rule = when (f.findingClass) {
            "tls-verification" -> TlsVerificationRule()
            "credentialed-cors" -> CredentialedCorsRule()
            else -> return null
        }
        val code = fix.trim().removePrefix("```kotlin").removePrefix("```").removeSuffix("```")
        val variants = listOf(code, "class __Fix {\n${wrapInFunction(code)}}\n")
        for (v in variants) {
            val (src, errs) = SastProjectLoader.parseKotlin("Fix.kt", v)
            if (errs.isNotEmpty()) continue
            val result = SastAnalyzer(listOf(rule)).analyze(SastProject(listOf(src), emptyMap(), emptyList()))
            return result.findings.none { it.sastClass == f.findingClass }
        }
        return false
    }
}
