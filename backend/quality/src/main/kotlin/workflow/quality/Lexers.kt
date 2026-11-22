package workflow.quality

/** I — идентификатор или ключевое слово, N — число, S — строка, P — знак. В Python перевод строки вне скобок — P "\n". */
class Tok(val kind: Char, val text: String, val start: Int, val end: Int) {
    override fun toString() = text
}

class LexError(val offset: Int, val message: String)

class Lexed(val tokens: List<Tok>, val error: LexError?)

private const val OPEN = "([{"
private const val CLOSE = ")]}"

private val PY_OPS3 = setOf("**=", "//=", ">>=", "<<=", "...")
private val PY_OPS2 = setOf("==", "!=", "<=", ">=", "->", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "//", "<<", ">>", "@=")
private val JS_OPS4 = setOf(">>>=")
private val JS_OPS3 = setOf("...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=")
private val JS_OPS2 = setOf("=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>")

private fun isIdStart(c: Char) = c == '_' || c == '$' || Character.isLetter(c)
private fun isIdPart(c: Char) = c == '_' || c == '$' || Character.isLetterOrDigit(c)

private class Brackets(val text: String, val index: LineIndex) {
    val stack = ArrayList<Pair<Char, Int>>()
    var error: LexError? = null
    fun open(c: Char, at: Int) { stack += c to at }
    fun close(c: Char, at: Int) {
        if (stack.isEmpty()) { fail(at, "Лишняя закрывающая скобка '$c'"); return }
        val (o, from) = stack.removeAt(stack.lastIndex)
        if (OPEN.indexOf(o) != CLOSE.indexOf(c)) fail(at, "Закрывающая скобка '$c' не соответствует '$o' из строки ${index.line(from)}")
    }
    fun fail(at: Int, message: String) { if (error == null) error = LexError(at, message) }
}

object PythonLexer {
    fun lex(text: String): Lexed {
        val index = LineIndex(text)
        val br = Brackets(text, index)
        val out = ArrayList<Tok>()
        var i = 0
        val n = text.length
        while (i < n) {
            val c = text[i]
            when {
                c == '\n' -> { if (br.stack.isEmpty() && out.isNotEmpty() && out.last().text != "\n") out += Tok('P', "\n", i, i + 1); i++ }
                c == ' ' || c == '\t' || c == '\u000c' -> i++
                c == '#' -> { while (i < n && text[i] != '\n') i++ }
                c == '\\' && i + 1 < n && text[i + 1] == '\n' -> i += 2
                c == '"' || c == '\'' -> i = string(text, i, i, out, br)
                isIdStart(c) -> {
                    var j = i
                    while (j < n && isIdPart(text[j])) j++
                    val word = text.substring(i, j)
                    if (j < n && (text[j] == '"' || text[j] == '\'') && word.length <= 2 && word.lowercase().all { it in "rbfu" }) {
                        i = string(text, i, j, out, br)
                    } else { out += Tok('I', word, i, j); i = j }
                }
                c.isDigit() || (c == '.' && i + 1 < n && text[i + 1].isDigit()) -> {
                    var j = i + 1
                    while (j < n && (isIdPart(text[j]) || text[j] == '.' || ((text[j] == '+' || text[j] == '-') && text[j - 1] in "eE" && !text.startsWith("0x", i, true)))) j++
                    out += Tok('N', text.substring(i, j), i, j); i = j
                }
                else -> {
                    val three = if (i + 3 <= n) text.substring(i, i + 3) else ""
                    val two = if (i + 2 <= n) text.substring(i, i + 2) else ""
                    val op = when { three in PY_OPS3 -> three; two in PY_OPS2 -> two; else -> c.toString() }
                    if (c in OPEN) br.open(c, i) else if (c in CLOSE) br.close(c, i)
                    else if (c in "?$`!" && op.length == 1) br.fail(i, "Недопустимый символ '$c'")
                    out += Tok('P', op, i, i + op.length); i += op.length
                }
            }
        }
        if (br.stack.isNotEmpty()) { val (o, at) = br.stack.first(); br.fail(at, "Скобка '$o' нигде не закрыта") }
        return Lexed(out, br.error)
    }

    /** [from] — начало токена (с префиксом), [quote] — позиция кавычки. */
    private fun string(text: String, from: Int, quote: Int, out: MutableList<Tok>, br: Brackets): Int {
        val q = text[quote]
        val triple = text.startsWith("$q$q$q", quote)
        var j = quote + if (triple) 3 else 1
        while (j < text.length) {
            val c = text[j]
            if (c == '\\') { j += 2; continue }
            if (triple) { if (text.startsWith("$q$q$q", j)) { j += 3; out += Tok('S', text.substring(from, j), from, j); return j } }
            else {
                if (c == q) { j++; out += Tok('S', text.substring(from, j), from, j); return j }
                if (c == '\n') break
            }
            j++
        }
        br.fail(from, if (triple) "Тройные кавычки не закрыты до конца файла" else "Строка не закрыта до конца строки")
        out += Tok('S', "\"\"", from, minOf(j, text.length))
        return minOf(j, text.length).let { if (triple) text.length else it }
    }
}

object JsLexer {
    private val regexAfterWords = setOf("return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await")

    fun lex(text: String): Lexed {
        val index = LineIndex(text)
        val br = Brackets(text, index)
        val out = ArrayList<Tok>()
        var i = 0
        val n = text.length
        if (text.startsWith("#!")) while (i < n && text[i] != '\n') i++
        var failed: LexError? = null
        while (i < n) {
            val c = text[i]
            when {
                c.isWhitespace() || c == '﻿' -> i++
                c == '/' && i + 1 < n && text[i + 1] == '/' -> { while (i < n && text[i] != '\n') i++ }
                c == '/' && i + 1 < n && text[i + 1] == '*' -> {
                    val end = text.indexOf("*/", i + 2)
                    if (end < 0) { failed = failed ?: LexError(i, "Комментарий не закрыт до конца файла"); i = n } else i = end + 2
                }
                c == '"' || c == '\'' -> {
                    var j = i + 1
                    var closed = false
                    while (j < n) {
                        val d = text[j]
                        if (d == '\\') { j += 2; continue }
                        if (d == c) { closed = true; j++; break }
                        if (d == '\n') break
                        j++
                    }
                    if (!closed) { failed = failed ?: LexError(i, "Invalid or unexpected token: строка не закрыта до конца строки"); j = minOf(j, n) }
                    out += Tok('S', "\"\"", i, j); i = j
                }
                c == '`' -> {
                    val end = templateEnd(text, i)
                    if (end < 0) { failed = failed ?: LexError(i, "Шаблонная строка не закрыта до конца файла"); i = n }
                    else { out += Tok('S', "``", i, end); i = end }
                }
                c == '/' && regexAllowed(out) -> {
                    val end = regexEnd(text, i)
                    if (end > 0) { out += Tok('S', "//", i, end); i = end }
                    else { out += Tok('P', "/", i, i + 1); i++ }
                }
                isIdStart(c) || c == '#' && i + 1 < n && isIdStart(text[i + 1]) -> {
                    var j = i + 1
                    while (j < n && isIdPart(text[j])) j++
                    out += Tok('I', text.substring(i, j), i, j); i = j
                }
                c.isDigit() || (c == '.' && i + 1 < n && text[i + 1].isDigit()) -> {
                    var j = i + 1
                    while (j < n && (isIdPart(text[j]) || text[j] == '.' || ((text[j] == '+' || text[j] == '-') && text[j - 1] in "eE" && !text.startsWith("0x", i, true)))) j++
                    out += Tok('N', text.substring(i, j), i, j); i = j
                }
                else -> {
                    val four = if (i + 4 <= n) text.substring(i, i + 4) else ""
                    val three = if (i + 3 <= n) text.substring(i, i + 3) else ""
                    val two = if (i + 2 <= n) text.substring(i, i + 2) else ""
                    val op = when { four in JS_OPS4 -> four; three in JS_OPS3 -> three; two in JS_OPS2 -> two; else -> c.toString() }
                    if (c in OPEN) br.open(c, i) else if (c in CLOSE) br.close(c, i)
                    out += Tok('P', op, i, i + op.length); i += op.length
                }
            }
        }
        var error = failed ?: br.error
        if (error == null && br.stack.isNotEmpty()) {
            val (o, at) = br.stack.last()
            val last = out.lastOrNull()?.start ?: 0
            error = LexError(last, "SyntaxError: Unexpected end of input (скобка '$o' из строки ${index.line(at)} не закрыта)")
        }
        return Lexed(out, error)
    }

    private fun regexAllowed(out: List<Tok>): Boolean {
        val prev = out.lastOrNull() ?: return true
        return when (prev.kind) {
            'N', 'S' -> false
            'I' -> prev.text in regexAfterWords
            else -> prev.text !in setOf(")", "]", "++", "--")
        }
    }

    private fun regexEnd(text: String, start: Int): Int {
        var j = start + 1
        var inClass = false
        while (j < text.length) {
            val c = text[j]
            if (c == '\n') return -1
            if (c == '\\') { j += 2; continue }
            if (c == '[') inClass = true else if (c == ']') inClass = false
            else if (c == '/' && !inClass) { j++; while (j < text.length && text[j].isLetter()) j++; return j }
            j++
        }
        return -1
    }

    private fun templateEnd(text: String, start: Int): Int {
        var j = start + 1
        while (j < text.length) {
            when (text[j]) {
                '\\' -> j += 2
                '`' -> return j + 1
                '$' -> if (j + 1 < text.length && text[j + 1] == '{') {
                    var depth = 1
                    j += 2
                    while (j < text.length && depth > 0) {
                        when (text[j]) {
                            '{' -> depth++
                            '}' -> depth--
                            '`' -> { val e = templateEnd(text, j); if (e < 0) return -1; j = e - 1 }
                            '/' -> {
                                val before = text.substring(start, j).trimEnd().lastOrNull()
                                if (before != null && before in "(,=:[!&|?{;" && text.getOrNull(j + 1) != '/' && text.getOrNull(j + 1) != '*') {
                                    val e = regexEnd(text, j)
                                    if (e > 0) j = e - 1
                                }
                            }
                            '"', '\'' -> { val q = text[j]; j++; while (j < text.length && text[j] != q && text[j] != '\n') { if (text[j] == '\\') j++; j++ } }
                        }
                        j++
                    }
                } else j++
                else -> j++
            }
        }
        return -1
    }
}

/** Индекс парной закрывающей скобки для открывающей в позиции [open]; -1 если нет. */
fun matching(tokens: List<Tok>, open: Int): Int {
    var depth = 0
    for (i in open until tokens.size) {
        val t = tokens[i]
        if (t.kind != 'P') continue
        if (t.text.length == 1 && t.text[0] in OPEN) depth++
        else if (t.text.length == 1 && t.text[0] in CLOSE) { depth--; if (depth == 0) return i }
    }
    return -1
}
