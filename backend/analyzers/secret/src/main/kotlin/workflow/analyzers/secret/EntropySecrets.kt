package workflow.analyzers.secret

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceType
import kotlin.math.ln

/*
 * Секрет по энтропии: строка, похожая на случайный ключ, даже если имя переменной ничего не говорит
 * (`val abc = "xK9mQ2vL8pZr4tW7nB3c"`). Именные правила ловят password/token/apiKey; это правило — то, что
 * между ними проскальзывает. Совет экспертов 21.11: пропуск хуже ложной тревоги, секреты не прятать.
 *
 * Отсев шума: обычные слова и идентификаторы (нет цифр или низкая энтропия), UUID, хеши и контрольные суммы
 * (по контексту строки), адреса без пароля (их пароль ловит urlPassword), JWT отдельно — у него точки.
 * Строка, где уже сработало именное правило или есть отклонённый кандидат, повторно не выдаётся.
 */

private val token = Regex("""[A-Za-z0-9+/=_-]{20,}""")
private val jwt = Regex("""eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}""")
private val wordRun = Regex("""[A-Z]?[a-z]{3,}""")
private val hexOnly = Regex("""[0-9a-fA-F]+""")
private val uuid = Regex("""(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}""")
private val hashContext = Regex("""(?i)sha\d*|md5|hash|checksum|digest|integrity|commit|etag|fingerprint|uuid|guid|version""")
// Начало только на границе слова и без возвратов: иначе длинная строка из букв даёт квадратичное время.
private val urlInLine = Regex("""(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*+://\S+""", RegexOption.IGNORE_CASE)
private const val MAX_ENTROPY_LINE = 100_000

/** Энтропия Шеннона в битах на символ. */
internal fun shannonEntropy(text: String): Double {
    if (text.isEmpty()) return 0.0
    return text.groupingBy { it }.eachCount().values.sumOf { count ->
        val p = count.toDouble() / text.length
        -p * ln(p) / ln(2.0)
    }
}

/** Похожа ли строка на случайный ключ. Порог зависит от алфавита: у hex он ниже, но и длина нужна больше. */
internal fun looksRandom(value: String): Boolean {
    val core = value.trimEnd('=')
    if (core.length < 20 || uuid.matches(value)) return false
    if (core.startsWith("-") || "--" in core || "__" in core) return false
    val hasDigit = core.any(Char::isDigit)
    val hasLetter = core.any(Char::isLetter)
    if (!hasDigit || !hasLetter) return false
    val entropy = shannonEntropy(core)
    if (hexOnly.matches(core)) return core.length >= 32 && entropy >= 3.0
    val mixedCase = core.any(Char::isUpperCase) && core.any(Char::isLowerCase)
    // Слова через дефис или подчёркивание (spring-boot-starter-web2, MAX_RETRY_2024) — не ключ.
    val separators = core.count { it == '-' || it == '_' }
    if (separators * 6 > core.length) return false
    // CamelCase-идентификатор (VeryLongClassName2Impl): почти вся строка состоит из слов вида Xxxx.
    val wordChars = wordRun.findAll(core).sumOf { it.value.length }
    if (wordChars * 10 >= core.length * 7) return false
    return entropy >= if (mixedCase) 3.7 else 4.0
}

/** Токен вплотную к `.` или `(` — вызов метода (`host.endsWith(x)`), а не значение. */
private fun isCodeIdentifierUse(line: String, range: IntRange): Boolean {
    val before = line.getOrNull(range.first - 1)
    val after = line.getOrNull(range.last + 1)
    return before == '.' || before == '(' || after == '(' || after == '.' || after == ')' || after == ','
}

private val base64Token = Regex("""[A-Za-z0-9+/_-]{2,}={0,2}""")
private val tellingWord = Regex("""(?i)pass|pwd|secret|token|key""")

/**
 * Короткий секрет, спрятанный в Base64 (`"cGFzc3dvcmQxMjM="` = password123): декодируем и смотрим, что внутри.
 * Возвращает расшифрованный текст, если он похож на пароль или ключ. Просто слова (`settings`) не подходят:
 * без цифры, `=` или смешанного регистра токен не рассматривается, а мусор после декодирования не печатается.
 */
internal fun decodedBase64Secret(value: String): String? {
    if (value.length < 8 || value.length % 4 != 0 || !base64Token.matches(value)) return null
    val core = value.trimEnd('=')
    val hasDigit = core.any(Char::isDigit)
    val mixedCase = core.any(Char::isUpperCase) && core.any(Char::isLowerCase)
    if (!hasDigit && !mixedCase && core.length == value.length) return null
    val bytes = try {
        java.util.Base64.getDecoder().decode(value.replace('-', '+').replace('_', '/'))
    } catch (_: IllegalArgumentException) {
        return null
    }
    if (bytes.size !in 6..128 || bytes.any { it < 0x21 || it > 0x7E }) return null
    val text = String(bytes, Charsets.US_ASCII)
    if (text.none(Char::isLetter)) return null
    // Слаги вроде public-label (буквы и дефисы) — не пароль; нужна цифра или иной символ.
    val symbolOrDigit = text.any { !it.isLetter() && it !in "-_." }
    return text.takeIf { symbolOrDigit || looksRandom(text) || tellingWord.containsMatchIn(text) }
}

/** 40/64 hex — git SHA-1 / SHA-256: хеш, а не секрет, если имя не говорит о ключе. */
private val gitOrSha256Hex = Regex("""(?i)[0-9a-f]{40}|[0-9a-f]{64}""")
private val tokenContext = Regex("""(?i)authorization|bearer|x-[\w-]*(?:token|auth)|\bauth\b|token|secret|credential""")
private val keyContext = Regex("""(?i)api[-_ ]?key|x-[\w-]*key|[a-z0-9]key\b|\bkey\b|licen[sc]e""")

/** Класс по контексту строки: заголовок, Bearer, токен → configuration-token; имя с key → api-key; без контекста — high-entropy. */
internal fun entropyKind(line: String): String = when {
    tokenContext.containsMatchIn(line) -> "configuration-token"
    keyContext.containsMatchIn(line) -> "api-key"
    else -> "high-entropy"
}

internal fun scanEntropySecrets(model: ProjectModel, known: Collection<Location>): List<SecretCandidate> {
    val taken = known.groupBy({ it.path }) { it.line..(it.endLine ?: it.line) }
    fun isTaken(path: String, line: Int) = taken[path].orEmpty().any { line in it }
    return buildList {
        for (file in model.files.filter { it.isBuiltInSecretSource() && it.type != SourceType.PEM && it.type != SourceType.SQL }) {
            file.text.lineSequence().forEachIndexed { index, line ->
                val lineNo = index + 1
                if (line.length > MAX_ENTROPY_LINE || isTaken(file.path, lineNo) || hashContext.containsMatchIn(line)) return@forEachIndexed
                val urls = urlInLine.findAll(line).map { it.range }.toList()
                val location = Location(file.path, lineNo)
                val jwtHit = jwt.find(line)?.value
                if (jwtHit != null) {
                    add(SecretCandidate(entropyKind(line), jwtHit, location))
                    return@forEachIndexed
                }
                val decoded = base64Token.findAll(line)
                    .filter { m -> !isCodeIdentifierUse(line, m.range) }
                    .filter { m -> urls.none { m.range.first in it } }
                    // «Basic <base64>» разбирает именное правило (логин:пароль); здесь не дублируем.
                    .filterNot { m -> line.substring(0, m.range.first).trimEnd().endsWith("Basic", ignoreCase = true) }
                    .firstOrNull { decodedBase64Secret(it.value) != null }
                if (decoded != null) {
                    add(SecretCandidate("recoverable-token", decoded.value, location))
                    return@forEachIndexed
                }
                val credentialNamed = tokenContext.containsMatchIn(line) || keyContext.containsMatchIn(line)
                token.findAll(line).filter { m -> urls.none { m.range.first in it } }.map { it.value }
                    .filterNot { !credentialNamed && gitOrSha256Hex.matches(it) }
                    .firstOrNull(::looksRandom)?.let { add(SecretCandidate(entropyKind(line), it, location)) }
            }
        }
    }
}
