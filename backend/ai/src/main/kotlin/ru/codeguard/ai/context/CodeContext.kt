package ru.codeguard.ai.context

import ru.codeguard.ai.model.AiFinding

/**
 * Фрагменты кода вокруг находок для промпта. Модели уходит только это — не весь репозиторий.
 *
 * Секреты не покидают периметр (несколько независимых барьеров — эвристика не последний рубеж):
 *  1. У SECRET-находок фрагмента нет вообще — модель получает класс, место и фиксированную маску.
 *  2. Строки, где анализатор нашёл секрет (основная и evidence), заменяются пометкой целиком в любом фрагменте.
 *  3. Комментарии вырезаются: в них не нужны для объяснения, зато через них идут подсказки-инъекции.
 *  4. Значения рядом с «секретными» именами маскируются в любом виде: "…", '…', """…""" (в т. ч. многострочные),
 *     YAML/properties без кавычек, значение на следующей строке, ${VAR:значение-по-умолчанию}, charArrayOf(…).
 *  5. Строки, похожие на ключ/токен по виду (длинные, буквы+цифры, Bearer, base64), маскируются независимо от имени.
 * Тот же [scrubText] применяется к метаданным находки в промпте и к ответу модели на выходе.
 */
class CodeContext(private val source: (String) -> String?, private val radius: Int = 3, private val maxLines: Int = 25) {

    /** Номера строк с найденными секретами по файлам — их нельзя показывать ни в каком фрагменте. */
    private var secretLines: Map<String, Set<Int>> = emptyMap()

    fun registerSecrets(findings: List<AiFinding>) {
        secretLines = findings.filter { it.category == "SECRET" }
            .flatMap { f ->
                // evidence учитываем независимо от наличия основной строки
                val main = f.line?.let { l -> (l..(f.endLine ?: l)).map { f.path to it } }.orEmpty()
                main + f.evidence.flatMap { e -> (e.line..(e.endLine ?: e.line)).map { e.path to it } }
            }
            .groupBy({ it.first }, { it.second }).mapValues { it.value.toSet() }
    }

    /** Фрагмент с номерами строк вида «13| код» или null, если файла нет / находка секретная. */
    fun snippet(f: AiFinding): String? {
        if (f.category == "SECRET") return null
        val line = f.line ?: return null
        val text = source(f.path) ?: return null
        // Сверхдлинные строки (минифицированный код, намеренный мусор) обрезаем до разбора: иначе regex уходит в StackOverflow.
        val lines = text.removePrefix("﻿").replace("\r\n", "\n").replace('\r', '\n').split('\n').map { it.take(1000) }
        val from = (line - radius).coerceAtLeast(1)
        val to = ((f.endLine ?: line) + radius).coerceAtMost(lines.size).coerceAtMost(from + maxLines - 1)
        val hidden = secretLines[f.path].orEmpty()
        // Маскируем по всему файлу до точки выхода — чтобы многострочные литералы и «значение на следующей строке» учитывали контекст выше.
        val scrubbed = scrubLines(lines.subList(0, to), isConfig(f.path))
        return (from..to).joinToString("\n") { n ->
            val content = if (n in hidden) "// [строка с секретом скрыта]" else scrubbed[n - 1].take(MAX_LINE)
            "$n| $content"
        }
    }

    companion object {
        const val MAX_LINE = 200
        const val MASK = "«скрыто»"

        private val SECRET_NAME = Regex("""(?i)(pass(word|wd|phrase)?|pwd|secret|token|api[-_.]?key|apikey|access[-_.]?key|private[-_.]?key|credential|auth(orization)?|bearer|jwt|signing|salt|cookie|session[-_.]?key|client[-_.]?secret|aes|hmac)""")
        private val DQ = Regex(""""((?:[^"\\]++|\\.)*+)"""")
        private val SQ = Regex("""'((?:[^'\\]++|\\.)*+)'""")
        private val SQL_WORDS = Regex("""(?i)\b(select|insert|update|delete|from|where|join|values)\b""")

        private fun isConfig(path: String) = path.endsWith(".yml") || path.endsWith(".yaml") || path.endsWith(".properties") || path.endsWith(".env") || path.endsWith(".conf")

        /** Маскирование строк файла с учётом контекста (многострочные """…""", значение на следующей строке, блоки YAML). */
        fun scrubLines(lines: List<String>, config: Boolean, keepComments: Boolean = false): List<String> {
            val out = ArrayList<String>(lines.size)
            var inRaw = false          // внутри """…"""
            var rawSecret = false      // этот """ открыт рядом с секретным именем
            var pendingName = false    // предыдущая строка: «секретное имя =» / «key: |» без значения
            var inBlockComment = false
            var yamlBlockIndent = -1   // внутри блока YAML «secret: |» — строки с отступом больше ключа маскируются целиком
            for ((index, original) in lines.withIndex()) {
                var line = original
                if (yamlBlockIndent >= 0) {
                    val indent = line.indexOfFirst { !it.isWhitespace() }
                    if (line.isBlank()) { out += line; continue }
                    if (indent > yamlBlockIndent) { out += line.substring(0, indent) + MASK; continue }
                    yamlBlockIndent = -1
                }
                // Конфиг: «password:» без значения → значение на следующей строке (простой скаляр с отступом)
                if (config && pendingName && line.isNotBlank() && !Regex("""^\s*-?\s*[\w.\-\[\]]+\s*[:=]""").containsMatchIn(line)) {
                    val indent = line.indexOfFirst { !it.isWhitespace() }
                    out += line.substring(0, indent) + MASK
                    pendingName = false
                    continue
                }
                // Блочные комментарии /* … */ (в том числе многострочные)
                if (inBlockComment && !keepComments) {
                    val end = line.indexOf("*/")
                    if (end < 0) { out += "// [комментарий удалён]"; continue }
                    line = line.substring(end + 2); inBlockComment = false
                }
                if (inRaw) {
                    val end = line.indexOf("\"\"\"")
                    val body = if (end < 0) line else line.substring(0, end)
                    val masked = if (rawSecret || looksLikeHighEntropy(body.trim())) MASK else scrubText(body)
                    out += if (end < 0) masked else masked + line.substring(end)
                    if (end >= 0) inRaw = false
                    continue
                }
                if (!keepComments) {
                    val (withoutComments, blockOpened) = stripComments(line)
                    line = withoutComments
                    inBlockComment = blockOpened
                }
                val nameHere = SECRET_NAME.containsMatchIn(keyPart(line, config))
                val secretContext = nameHere || pendingName
                // """ на этой строке без закрытия
                val rawStart = line.indexOf("\"\"\"")
                if (rawStart >= 0 && line.indexOf("\"\"\"", rawStart + 3) < 0) {
                    inRaw = true
                    // Содержимое литерала целиком (до закрывающих """): SQL нужен модели и не маскируется.
                    val rawBody = buildString {
                        append(line.substring(rawStart + 3))
                        for (next in lines.drop(index + 1)) { val e = next.indexOf("\"\"\""); append('\n').append(if (e < 0) next else next.substring(0, e)); if (e >= 0) break }
                    }
                    val sqlish = SQL_WORDS.containsMatchIn(rawBody)
                    rawSecret = secretContext && !sqlish
                    out += scrubLine(line.substring(0, rawStart), secretContext, config) + "\"\"\"" +
                        line.substring(rawStart + 3).let { if (rawSecret) (if (it.isBlank()) it else MASK) else scrubText(it) }
                    pendingName = false
                    continue
                }
                out += scrubLine(line, secretContext, config)
                // «val password =» / «password:» / «password: |» — значение будет на следующей строке
                val trimmed = line.trimEnd()
                pendingName = nameHere && (trimmed.endsWith("=") || trimmed.endsWith(":") || trimmed.endsWith("|") || trimmed.endsWith(">") || trimmed.endsWith("(") || trimmed.endsWith("+"))
                // Блочный скаляр YAML: «password: |» / «password: >-» — маскируем все строки блока
                if (config && nameHere && Regex("""[:=]\s*[|>][+-]?\s*$""").containsMatchIn(trimmed)) {
                    yamlBlockIndent = line.indexOfFirst { !it.isWhitespace() }
                    pendingName = false
                }
            }
            return out
        }

        /** Удаляет //-комментарий (вне строк) и начало /* … */; возвращает строку и признак незакрытого блочного комментария. */
        private fun stripComments(line: String): Pair<String, Boolean> {
            var inStr = false
            var quote = ' '
            var i = 0
            while (i < line.length) {
                val c = line[i]
                if (inStr) {
                    if (c == '\\') { i += 2; continue }
                    if (c == quote) inStr = false
                } else {
                    if (c == '"' || c == '\'') { inStr = true; quote = c }
                    else if (c == '/' && i + 1 < line.length && line[i + 1] == '/') return line.substring(0, i).trimEnd() + (if (line.substring(0, i).isBlank()) "// [комментарий удалён]" else "") to false
                    else if (c == '#' && i == line.indexOfFirst { !it.isWhitespace() }) return "# [комментарий удалён]" to false
                    else if (c == '/' && i + 1 < line.length && line[i + 1] == '*') {
                        val end = line.indexOf("*/", i + 2)
                        return if (end < 0) line.substring(0, i).trimEnd() to true
                        else stripComments(line.substring(0, i) + line.substring(end + 2))
                    }
                }
                i++
            }
            return line to false
        }

        /** Часть строки, где стоит имя: до первой кавычки; для конфигов — ключ до «:» или «=». */
        private fun keyPart(line: String, config: Boolean): String {
            val beforeQuote = line.substringBefore('"').substringBefore('\'')
            if (!config) return beforeQuote
            return Regex("""^\s*-?\s*([\w.\-\[\]]+)\s*[:=]""").find(line)?.groupValues?.get(1) ?: beforeQuote
        }

        /** Маскирует значения в одной строке с учётом «секретного» контекста. */
        private fun scrubLine(line: String, secretContext: Boolean, config: Boolean): String {
            var s = line
            // ${VAR:значение} — значение по умолчанию маскируем всегда, когда рядом секретное имя или значение похоже на секрет
            s = Regex("""\$\{([A-Za-z0-9_.\-]+):([^}]*)}""").replace(s) { m ->
                val v = m.groupValues[2]
                if (v.isEmpty()) m.value else if (secretContext || looksLikeHighEntropy(v) || v.length >= 6) "\${${m.groupValues[1]}:$MASK}" else m.value
            }
            // charArrayOf('a','b',…) рядом с секретным именем
            if (secretContext) s = Regex("""charArrayOf\([^)]*\)""").replace(s, "charArrayOf($MASK)")
            // Литералы в кавычках
            s = DQ.replace(s) { m -> maskLiteral(m.value, m.groupValues[1], '"', secretContext) }
            s = SQ.replace(s) { m -> if (m.groupValues[1].length <= 1) m.value else maskLiteral(m.value, m.groupValues[1], '\'', secretContext) }
            // YAML/properties/env без кавычек: key: value / key=value
            if (config) {
                Regex("""^(\s*-?\s*[\w.\-\[\]]+\s*[:=]\s*)([^"'#\s|>][^#]*?)\s*$""").find(s)?.let { m ->
                    val key = m.groupValues[1]
                    val value = m.groupValues[2]
                    val isEnvRef = Regex("""^\$\{[A-Za-z0-9_.\-]+}$""").matches(value)
                    if (!isEnvRef && (SECRET_NAME.containsMatchIn(key) || looksLikeHighEntropy(value) || value.lowercase().startsWith("bearer "))) s = key + MASK
                }
            }
            return scrubText(s)
        }

        private fun maskLiteral(whole: String, value: String, q: Char, secretContext: Boolean): String = when {
            value.isEmpty() -> whole
            Regex("""^\$\{[A-Za-z0-9_.\-]+}$""").matches(value) -> whole            // ${ENV} без значения по умолчанию — безопасно
            secretContext && !isPlaceholder(value) && !SQL_WORDS.containsMatchIn(value) -> "$q$MASK$q"
            looksLikeHighEntropy(value) -> "$q$MASK$q"
            else -> whole
        }

        /**
         * Маскирование свободного текста (метаданные находок, ответ модели, сообщения об ошибках):
         * Bearer-токены, длинные «случайные» строки, base64, пары «секретное_имя=значение».
         */
        fun scrubText(text: String): String {
            var s = Regex("""(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{6,}""").replace(text, "Bearer $MASK")
            // группы: 1 имя, 2 (word|wd), 3 разделитель, 4 кавычка, 5 значение, 6 закрывающая кавычка; код вида getenv(…) не трогаем
            s = Regex("""(?i)\b(pass(word|wd)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|client[-_]?secret)\b(\s*[:=]\s*)(["']?)([^\s"',;()]{3,})(["']?)(?![\w(.])""").replace(s) { m ->
                val value = m.groupValues[5]
                if (value == MASK || Regex("""^\$\{[A-Za-z0-9_.\-]+}$""").matches(value)) m.value
                else "${m.groupValues[1]}${m.groupValues[3]}${m.groupValues[4]}$MASK${m.groupValues[6]}"
            }
            s = Regex("""[A-Za-z0-9_\-+/=]{16,}""").replace(s) { m -> if (looksLikeHighEntropy(m.value)) MASK else m.value }
            return s
        }

        private fun isPlaceholder(v: String) = Regex("""(?i)^(your[_-]|changeme|example|placeholder|xxx+|\*+$|<.*>$|todo|test$)""").containsMatchIn(v)

        /** Похоже на ключ/токен по виду: длинная строка без пробелов, буквы и цифры вперемешку, или base64. */
        fun looksLikeHighEntropy(v: String): Boolean {
            if (v.length < 12 || v.contains(' ')) return false
            if (v.startsWith("http") || v.contains("://") || v.startsWith("/") || v.startsWith("\${")) return false
            // Идентификаторы уязвимостей и координаты зависимостей — не секреты
            if (Regex("""(?i)^(GHSA(-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,7})$""").matches(v)) return false
            if (Regex("""^[\w.\-]+:[\w.\-]+(:[\w.\-]+)?$""").matches(v) && v.contains('.')) return false
            if (Regex("""^[a-z]+([._\-][a-z]+)+$""").matches(v)) return false                    // имена: spring.datasource.url, foo-bar
            if (Regex("""^[A-Z][A-Za-z]+$""").matches(v) || Regex("""^[a-z]+([A-Z][a-z]+)+$""").matches(v)) return false // ИменаКлассов, camelCase
            val classes = listOf(Regex("[a-z]"), Regex("[A-Z]"), Regex("[0-9]")).count { it.containsMatchIn(v) }
            val base64 = v.length >= 16 && Regex("""^[A-Za-z0-9+/]+={0,2}$""").matches(v) && classes >= 2 && Regex("[0-9]").containsMatchIn(v)
            return classes >= 3 || (classes >= 2 && v.length >= 20 && Regex("""[_\-]""").containsMatchIn(v)) || base64
        }
    }
}
