package workflow.quality

import org.springframework.stereotype.Component

@Component
class PythonChecker : LanguageChecker {
    override val language = "python"
    override val extensions = setOf("py")
    override val rules = listOf(
        QualityRule("python.syntax", DiagnosticKind.SYNTAX, language, "Синтаксис Python",
            "Незакрытые скобки и строки, лишние закрывающие скобки, составной оператор без двоеточия."),
        QualityRule("python.type.annotation-literal", DiagnosticKind.TYPE_MISMATCH, language, "Литерал не подходит по аннотации",
            "Литерал присваивается или возвращается туда, где аннотацией объявлен несовместимый простой тип (int, float, str, bool)."),
        QualityRule("python.reference.unresolved", DiagnosticKind.UNRESOLVED_REFERENCE, language, "Имя нигде не определено",
            "Имя читается, но нигде в модуле не присваивается, не импортируется и не является встроенным."),
        QualityRule("python.defect.mutable-default", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Изменяемое значение параметра по умолчанию",
            "Список, словарь или множество в значении по умолчанию создаётся один раз и разделяется между вызовами."),
        QualityRule("python.defect.shared-reference", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Умножение списка списков",
            "[[x] * n] * m повторяет одну и ту же вложенную строку: изменение одной ячейки меняет все строки."),
        QualityRule("python.defect.iterator-consumed", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Параметр обходится дважды",
            "Параметр сначала проходит any/all/sum, затем снова обходится: одноразовый итератор уже исчерпан."),
        QualityRule("python.defect.identity-literal", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Сравнение литерала через is",
            "is сравнивает идентичность, а не значение; результат для строк и чисел зависит от реализации."),
    )

    class Line(val tokens: List<Tok>, val indent: Int)

    override fun check(files: List<SourceUnit>, deadline: Deadline): LanguageResult {
        val diagnostics = mutableListOf<QualityDiagnostic>()
        val skipped = mutableListOf<SkippedFile>()
        var analyzed = 0
        for (file in files) {
            if (deadline.expired) { skipped += SkippedFile(file.path, "Не хватило времени"); continue }
            analyzed++
            val index = LineIndex(file.text)
            val lexed = PythonLexer.lex(file.text)
            fun add(kind: DiagnosticKind, rule: String, offset: Int, message: String, confidence: Confidence = Confidence.PROVEN) {
                diagnostics += QualityDiagnostic(kind, rule, language, file.path, index.line(offset), index.column(offset), message, confidence)
            }
            val lines = splitLines(lexed.tokens, index)
            val syntax = lexed.error?.let { listOf(it.offset to it.message) } ?: colonErrors(lines)
            if (syntax.isNotEmpty()) {
                syntax.forEach { (offset, message) -> add(DiagnosticKind.SYNTAX, "python.syntax", offset, "Синтаксическая ошибка: $message") }
                continue
            }
            Analysis(lines, ::add).run()
        }
        return LanguageResult(diagnostics, analyzed, skipped)
    }

    private fun splitLines(tokens: List<Tok>, index: LineIndex): List<Line> {
        val lines = ArrayList<Line>()
        var current = ArrayList<Tok>()
        for (t in tokens) {
            if (t.kind == 'P' && t.text == "\n") {
                if (current.isNotEmpty()) lines += Line(current, index.column(current.first().start) - 1)
                current = ArrayList()
            } else current += t
        }
        if (current.isNotEmpty()) lines += Line(current, index.column(current.first().start) - 1)
        return lines
    }

    private val compound = setOf("def", "class", "if", "elif", "else", "for", "while", "try", "except", "finally", "with")

    private fun colonErrors(lines: List<Line>): List<Pair<Int, String>> {
        val errors = mutableListOf<Pair<Int, String>>()
        for (line in lines) {
            val first = line.tokens.first()
            val head = if (first.text == "async" && line.tokens.size > 1) line.tokens[1] else first
            if (head.kind != 'I' || head.text !in compound) continue
            if (head.text == "class" && line.tokens.size < 2) continue
            var depth = 0
            var colon = false
            for (t in line.tokens) {
                if (t.kind != 'P') continue
                if (t.text in setOf("(", "[", "{")) depth++ else if (t.text in setOf(")", "]", "}")) depth--
                else if (t.text == ":" && depth == 0) colon = true
            }
            if (!colon) errors += line.tokens.last().end to "expected ':'"
        }
        return errors.take(1)
    }

    private val keywords = setOf("False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
        "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass",
        "raise", "return", "try", "while", "with", "yield", "match", "case", "type", "print", "exec", "self")

    private val builtins = ("abs aiter all anext any ascii bin bool breakpoint bytearray bytes callable chr classmethod compile complex copyright credits " +
        "delattr dict dir divmod enumerate eval exec exit filter float format frozenset getattr globals hasattr hash help hex id input int isinstance " +
        "issubclass iter len license list locals map max memoryview min next object oct open ord pow print property quit range repr reversed round set " +
        "setattr slice sorted staticmethod str sum super tuple type vars zip __import__ __name__ __file__ __doc__ __package__ __spec__ __loader__ " +
        "__builtins__ __debug__ __class__ __dict__ __path__ NotImplemented Ellipsis BaseException Exception ArithmeticError AssertionError AttributeError " +
        "BufferError EOFError FloatingPointError GeneratorExit ImportError IndentationError IndexError KeyboardInterrupt KeyError LookupError MemoryError " +
        "ModuleNotFoundError NameError NotImplementedError OSError OverflowError RecursionError ReferenceError RuntimeError StopAsyncIteration StopIteration " +
        "SyntaxError SystemError SystemExit TabError TimeoutError TypeError UnboundLocalError UnicodeDecodeError UnicodeEncodeError UnicodeError " +
        "UnicodeTranslateError ValueError ZeroDivisionError EnvironmentError IOError WindowsError Warning UserWarning DeprecationWarning " +
        "PendingDeprecationWarning SyntaxWarning RuntimeWarning FutureWarning ImportWarning UnicodeWarning BytesWarning ResourceWarning " +
        "ConnectionError BrokenPipeError ConnectionAbortedError ConnectionRefusedError ConnectionResetError BlockingIOError ChildProcessError " +
        "FileExistsError FileNotFoundError InterruptedError IsADirectoryError NotADirectoryError PermissionError ProcessLookupError ExceptionGroup " +
        "BaseExceptionGroup EncodingWarning").split(" ").toSet()

    private class Analysis(val lines: List<Line>, val add: (DiagnosticKind, String, Int, String, Confidence) -> Unit) {
        fun add(kind: DiagnosticKind, rule: String, offset: Int, message: String) = add(kind, rule, offset, message, Confidence.PROVEN)
        val owner = PythonChecker()

        fun run() {
            references()
            for ((i, line) in lines.withIndex()) {
                if (line.tokens.first().text == "def" || (line.tokens.first().text == "async" && line.tokens.getOrNull(1)?.text == "def")) function(i)
                sharedReference(line.tokens)
                identityLiteral(line.tokens)
                annotatedAssignment(line.tokens)
            }
        }

        // ---------- ссылки ----------

        private fun references() {
            val defined = hashSetOf<String>()
            var dynamic = false
            for (line in lines) {
                val t = line.tokens
                val head = t.first().text
                if (head == "import") {
                    var expectName = true
                    var k = 1
                    while (k < t.size) {
                        if (expectName && t[k].kind == 'I') {
                            var m = k
                            while (m + 2 < t.size && t[m + 1].text == "." && t[m + 2].kind == 'I') m += 2
                            if (m + 2 < t.size && t[m + 1].text == "as") { defined += t[m + 2].text; k = m + 3 } else { defined += t[k].text; k = m + 1 }
                            expectName = false
                            continue
                        }
                        if (t[k].text == ",") expectName = true
                        k++
                    }
                    continue
                }
                if (head == "from") {
                    val at = t.indexOfFirst { it.text == "import" }
                    if (at < 0) continue
                    var k = at + 1
                    while (k < t.size) {
                        if (t[k].text == "*") dynamic = true
                        else if (t[k].kind == 'I' && t[k].text != "as") {
                            if (k + 2 < t.size && t[k + 1].text == "as") { defined += t[k + 2].text; k += 2 } else defined += t[k].text
                        }
                        k++
                    }
                    continue
                }
                if (t.size >= 2 && t[0].kind == 'I' && t[1].text == ":") defined += t[0].text
                if (head == "global" || head == "nonlocal") { t.drop(1).filter { it.kind == 'I' }.forEach { defined += it.text }; continue }
                if (head == "case") t.filter { it.kind == 'I' }.forEach { defined += it.text }
                var depth = 0
                var lastEq = -1
                for ((k, tok) in t.withIndex()) {
                    if (tok.kind == 'P') {
                        if (tok.text in setOf("(", "[", "{")) depth++ else if (tok.text in setOf(")", "]", "}")) depth--
                        else if (depth == 0 && (tok.text == "=" || tok.text == ":=" || (tok.text.length >= 2 && tok.text.endsWith("=") && tok.text !in setOf("==", "!=", "<=", ">=")))) lastEq = k
                        else if (tok.text == ":=") lastEq = k
                    }
                    if (tok.kind != 'I') continue
                    when (tok.text) {
                        "def", "class" -> t.getOrNull(k + 1)?.takeIf { it.kind == 'I' }?.let { defined += it.text }
                        "as" -> t.getOrNull(k + 1)?.takeIf { it.kind == 'I' }?.let { defined += it.text }
                        "for" -> { var m = k + 1; while (m < t.size && t[m].text != "in") { if (t[m].kind == 'I') defined += t[m].text; m++ } }
                        "lambda" -> { var m = k + 1; while (m < t.size && t[m].text != ":") { if (t[m].kind == 'I') defined += t[m].text; m++ } }
                    }
                }
                if (t.any { it.kind == 'P' && it.text == ":=" }) t.forEachIndexed { k, tok -> if (tok.text == ":=" && k > 0 && t[k - 1].kind == 'I') defined += t[k - 1].text }
                if (lastEq > 0) for (k in 0 until lastEq) if (t[k].kind == 'I' && t.getOrNull(k - 1)?.text != ".") defined += t[k].text
                if (head == "def" || head == "async") defParameters(t).forEach { defined += it.first }
                if (t.any { it.text == "exec" || it.text == "globals" || it.text == "locals" || it.text == "__dict__" || it.text == "setattr" }) dynamic = true
            }
            if (dynamic) return
            val known = defined + builtinsAll
            val seen = hashSetOf<String>()
            for (line in lines) {
                val t = line.tokens
                if (t.first().text == "import" || t.first().text == "from") continue
                var depth = 0
                for ((k, tok) in t.withIndex()) {
                    if (tok.kind == 'P') { if (tok.text in setOf("(", "[", "{")) depth++ else if (tok.text in setOf(")", "]", "}")) depth--; continue }
                    if (tok.kind != 'I' || tok.text in pyKeywords || tok.text in known) continue
                    if (t.getOrNull(k - 1)?.text == ".") continue
                    if (depth > 0 && t.getOrNull(k + 1)?.text == "=") continue
                    if (!seen.add("${tok.text}@${tok.start}")) continue
                    val hint = closeName(tok.text, known.filter { it !in builtinsAll })
                    add(DiagnosticKind.UNRESOLVED_REFERENCE, "python.reference.unresolved", tok.start,
                        "Неразрешённая ссылка '${tok.text}'." + (hint?.let { " Возможно, имелось в виду '$it'." } ?: ""))
                }
            }
        }

        private val builtinsAll get() = owner.builtins
        private val pyKeywords get() = owner.keywords - setOf("print", "exec", "self", "type", "match", "case")

        // ---------- функции ----------

        /** Параметры def: (имя, значение по умолчанию или пусто). */
        private fun defParameters(t: List<Tok>): List<Pair<String, List<Tok>>> {
            val open = t.indexOfFirst { it.text == "(" }
            if (open < 0) return emptyList()
            val close = matching(t, open)
            if (close < 0) return emptyList()
            val result = ArrayList<Pair<String, List<Tok>>>()
            var depth = 0
            var k = open + 1
            while (k < close) {
                val tok = t[k]
                if (tok.kind == 'P') {
                    if (tok.text in setOf("(", "[", "{")) depth++ else if (tok.text in setOf(")", "]", "}")) depth--
                }
                if (depth == 0 && tok.kind == 'I' && t[k - 1].text in setOf("(", ",", "*", "**")) {
                    var m = k + 1
                    var d = 0
                    var defaultStart = -1
                    while (m < close) {
                        val x = t[m]
                        if (x.kind == 'P') {
                            if (x.text in setOf("(", "[", "{")) d++ else if (x.text in setOf(")", "]", "}")) d--
                            else if (d == 0 && x.text == "," ) break
                            else if (d == 0 && x.text == "=" && defaultStart < 0) defaultStart = m + 1
                        }
                        m++
                    }
                    result += tok.text to (if (defaultStart >= 0) t.subList(defaultStart, m) else emptyList())
                    k = m
                    continue
                }
                k++
            }
            return result
        }

        private fun bodyOf(defIndex: Int): List<Line> {
            val def = lines[defIndex]
            val body = ArrayList<Line>()
            var k = defIndex + 1
            while (k < lines.size && lines[k].indent > def.indent) { body += lines[k]; k++ }
            return body
        }

        private fun function(index: Int) {
            val line = lines[index]
            val t = line.tokens
            val params = defParameters(t)
            val body = bodyOf(index)
            val bodyTokens = body.flatMap { it.tokens }
            for ((name, default) in params) {
                if (default.isEmpty()) continue
                val mutable = default.first().text in setOf("[", "{") || (default.size >= 3 && default.first().text in setOf("list", "dict", "set") &&
                    default[1].text == "(" && default[2].text == ")")
                if (!mutable) continue
                val mutated = isMutated(name, bodyTokens)
                val at = default.first().start
                if (mutated) add(DiagnosticKind.FUNCTIONAL_DEFECT, "python.defect.mutable-default", at,
                    "Параметр '$name' имеет изменяемое значение по умолчанию и изменяется в теле: состояние сохраняется между вызовами. Используйте None и создавайте коллекцию внутри.")
                else add(DiagnosticKind.FUNCTIONAL_DEFECT, "python.defect.mutable-default", at,
                    "Параметр '$name' имеет изменяемое значение по умолчанию: оно создаётся один раз на все вызовы. Используйте None.", Confidence.LIKELY)
            }
            iteratorConsumed(params.map { it.first }, bodyTokens)
            returnTypes(t, body)
        }

        private val mutators = setOf("append", "extend", "add", "update", "insert", "pop", "remove", "clear", "setdefault", "sort", "reverse", "popitem", "discard")

        private fun isMutated(name: String, tokens: List<Tok>): Boolean {
            for ((k, tok) in tokens.withIndex()) {
                if (tok.kind != 'I' || tok.text != name || tokens.getOrNull(k - 1)?.text == ".") continue
                val next = tokens.getOrNull(k + 1) ?: continue
                if (next.text == "." && tokens.getOrNull(k + 2)?.text in mutators) return true
                if (next.text == "[") { val close = matching(tokens, k + 1); val after = tokens.getOrNull(close + 1)?.text
                    if (close > 0 && after != null && (after == "=" || (after.endsWith("=") && after !in setOf("==", "!=", "<=", ">=")))) return true }
                if (next.text in setOf("+=", "-=", "*=", "|=", "&=")) return true
            }
            return false
        }

        private fun iteratorConsumed(params: List<String>, tokens: List<Tok>) {
            val consuming = setOf("any", "all", "sum", "min", "max", "next", "sorted", "set", "tuple", "list", "len")
            for (name in params) {
                val iterations = tokens.indices.filter { k -> tokens[k].text == "in" && tokens.getOrNull(k + 1)?.text == name && tokens.getOrNull(k + 2)?.text.let { it == null || it != "." && it != "[" && it != "(" } }
                if (iterations.size < 2) continue
                if (tokens.any { it.text == "iter" || it.text == "tee" } && false) continue
                val first = iterations.first()
                // Первый обход находится внутри вызова any/all/sum/...: ищем ближайшую охватывающую открывающую скобку.
                var depth = 0
                var k = first
                var caller: String? = null
                while (k >= 0) {
                    val x = tokens[k]
                    if (x.text in setOf(")", "]", "}")) depth++
                    else if (x.text in setOf("(", "[", "{")) { if (depth == 0) { caller = tokens.getOrNull(k - 1)?.text; break } else depth-- }
                    k--
                }
                if (caller !in consuming) continue
                val materialized = tokens.indices.any { m -> tokens[m].text == name && tokens.getOrNull(m - 1)?.text == "(" && tokens.getOrNull(m - 2)?.text in setOf("list", "tuple", "set", "sorted") || tokens[m].text == name && tokens.getOrNull(m + 1)?.text == "=" }
                if (materialized) continue
                add(DiagnosticKind.FUNCTIONAL_DEFECT, "python.defect.iterator-consumed", tokens[iterations[1]].start,
                    "Параметр '$name' обходится повторно после $caller(...): для одноразового итератора (iter(...), генератор) второй обход пуст. Обойдите его один раз или материализуйте через list().",
                    Confidence.LIKELY)
            }
        }

        // ---------- типы ----------

        private fun literalType(t: Tok): String? = when {
            t.kind == 'N' -> if (t.text.startsWith("0x", true)) "int" else if (t.text.contains('.') || (t.text.contains('e', true) && !t.text.startsWith("0x", true))) "float" else "int"
            t.kind == 'S' -> if (t.text.first().lowercaseChar() in "bf") null else if (t.text.first().lowercaseChar() == 'b') "bytes" else "str"
            t.kind == 'I' && (t.text == "True" || t.text == "False") -> "bool"
            t.kind == 'I' && t.text == "None" -> "None"
            else -> null
        }

        private fun ok(expected: String, actual: String) = when (expected) {
            "int" -> actual == "int" || actual == "bool"
            "float" -> actual == "int" || actual == "float" || actual == "bool"
            "str" -> actual == "str"
            "bool" -> actual == "bool"
            else -> true
        }

        private val simple = setOf("int", "float", "str", "bool")

        private fun mismatch(expected: String, tok: Tok, what: String) {
            val actual = literalType(tok) ?: return
            if (ok(expected, actual)) return
            add(DiagnosticKind.TYPE_MISMATCH, "python.type.annotation-literal", tok.start, "Несовместимые типы: $what '$expected', найден литерал типа '$actual'.")
        }

        private fun annotatedAssignment(t: List<Tok>) {
            if (t.size >= 5 && t[0].kind == 'I' && t[1].text == ":" && t[2].text in simple && t[3].text == "=" && t.size == 5) mismatch(t[2].text, t[4], "объявленный тип")
        }

        private fun returnTypes(header: List<Tok>, body: List<Line>) {
            val arrow = header.indexOfFirst { it.text == "->" }
            if (arrow < 0 || arrow + 3 != header.size || header[arrow + 1].text !in simple || header.last().text != ":") return
            val expected = header[arrow + 1].text
            var skipIndent = -1
            for (line in body) {
                if (skipIndent >= 0) { if (line.indent > skipIndent) continue else skipIndent = -1 }
                val f = line.tokens.first().text
                if (f == "def" || f == "class" || (f == "async" && line.tokens.getOrNull(1)?.text == "def")) { skipIndent = line.indent; continue }
                if (f == "return" && line.tokens.size == 2) mismatch(expected, line.tokens[1], "возвращаемый тип")
            }
        }

        // ---------- прочие дефекты ----------

        private fun sharedReference(t: List<Tok>) {
            for (open in t.indices) {
                if (t[open].text != "[" || t.getOrNull(open + 1)?.text != "[") continue
                val close = matching(t, open)
                if (close < 0 || t.getOrNull(close + 1)?.text != "*") continue
                if ((open + 1 until close).any { t[it].text == "for" && depthOf(t, open + 1, it) == 0 }) continue
                val inner = matching(t, open + 1)
                if (inner < 0 || inner > close) continue
                // внешний список состоит из одной вложенной строки, возможно с умножением: [[0] * n] * m
                add(DiagnosticKind.FUNCTIONAL_DEFECT, "python.defect.shared-reference", t[open].start,
                    "Список списков умножается на число: все строки — одна и та же ссылка, изменение одной ячейки меняет каждую строку. Используйте [[...] for _ in range(n)].")
            }
        }

        private fun depthOf(t: List<Tok>, from: Int, to: Int): Int {
            var d = 0
            for (k in from until to) { if (t[k].text in setOf("(", "[", "{")) d++ else if (t[k].text in setOf(")", "]", "}")) d-- }
            return d
        }

        private fun identityLiteral(t: List<Tok>) {
            for (k in t.indices) {
                if (t[k].kind != 'I' || t[k].text != "is") continue
                var r = k + 1
                if (t.getOrNull(r)?.text == "not") r++
                val right = t.getOrNull(r) ?: continue
                val left = t.getOrNull(k - 1) ?: continue
                val literal = (right.kind == 'S' || right.kind == 'N') || (left.kind == 'S' || left.kind == 'N')
                if (literal) add(DiagnosticKind.FUNCTIONAL_DEFECT, "python.defect.identity-literal", t[k].start,
                    "Оператор is сравнивает идентичность объектов, а не значения: со строкой или числом результат непредсказуем. Используйте == или !=.")
            }
        }
    }
}
