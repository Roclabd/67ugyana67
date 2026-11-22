package workflow.quality

import org.springframework.stereotype.Component

@Component
class JavaScriptChecker : LanguageChecker {
    override val language = "javascript"
    override val extensions = setOf("js", "mjs", "cjs")
    override val rules = listOf(
        QualityRule("javascript.syntax", DiagnosticKind.SYNTAX, language, "Синтаксис JavaScript",
            "Незакрытые скобки, строки, шаблоны и комментарии; лишние закрывающие скобки; конец файла внутри блока."),
        QualityRule("javascript.type.literal-arithmetic", DiagnosticKind.TYPE_MISMATCH, language, "Арифметика с несовместимыми литералами",
            "Литерал-объект, массив или функция в арифметическом выражении, а также вычитание/деление строковых литералов с числами."),
        QualityRule("javascript.reference.unresolved", DiagnosticKind.UNRESOLVED_REFERENCE, language, "Имя похоже на опечатку",
            "Имя не объявлено в файле и не является глобальным, но отличается от объявленного на одну-две буквы."),
        QualityRule("javascript.defect.array-equality", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Сравнение с литералом массива или объекта",
            "== и === сравнивают ссылки: сравнение с новым литералом всегда ложно."),
        QualityRule("javascript.defect.nan-comparison", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Сравнение с NaN",
            "x === NaN всегда ложно; нужен Number.isNaN."),
        QualityRule("javascript.defect.falsy-fallback", DiagnosticKind.FUNCTIONAL_DEFECT, language, "Запасное значение через ||",
            "return param || число заменяет и допустимый 0; нужен ??."),
        QualityRule("javascript.defect.default-sort", DiagnosticKind.FUNCTIONAL_DEFECT, language, "sort() без компаратора для чисел",
            "Сортировка по умолчанию сравнивает строки: [10, 2, -3] станет [-3, 10, 2]."),
        QualityRule("javascript.defect.unawaited-map", DiagnosticKind.FUNCTIONAL_DEFECT, language, "map с асинхронной функцией без Promise.all",
            "async-функция возвращает массив промисов вместо значений."),
    )

    private class Fn(val name: String?, val params: Set<String>, val async: Boolean, val bodyStart: Int, val bodyEnd: Int)

    override fun check(files: List<SourceUnit>, deadline: Deadline): LanguageResult {
        val diagnostics = mutableListOf<QualityDiagnostic>()
        val skipped = mutableListOf<SkippedFile>()
        var analyzed = 0
        for (file in files) {
            if (deadline.expired) { skipped += SkippedFile(file.path, "Не хватило времени"); continue }
            analyzed++
            val index = LineIndex(file.text)
            val lexed = JsLexer.lex(file.text)
            fun add(kind: DiagnosticKind, rule: String, offset: Int, message: String, confidence: Confidence = Confidence.PROVEN) {
                diagnostics += QualityDiagnostic(kind, rule, language, file.path, index.line(offset), index.column(offset), message, confidence)
            }
            lexed.error?.let { add(DiagnosticKind.SYNTAX, "javascript.syntax", it.offset, "Синтаксическая ошибка: ${it.message}"); continue }
            val t = lexed.tokens
            val functions = functions(t)
            references(t, ::add)
            literalArithmetic(t, ::add)
            equality(t, ::add)
            for (fn in functions) functionDefects(t, fn, ::add)
            sortDefects(t, functions, ::add)
        }
        return LanguageResult(diagnostics, analyzed, skipped)
    }

    private val notFunctionHeads = setOf("if", "for", "while", "switch", "catch", "with", "function", "return", "typeof", "new", "await", "do", "else", "in", "of")

    private fun functions(t: List<Tok>): List<Fn> {
        val result = ArrayList<Fn>()
        fun params(open: Int): Set<String> {
            val close = matching(t, open)
            return if (close < 0) emptySet() else (open + 1 until close).filter { t[it].kind == 'I' }.map { t[it].text }.toSet()
        }
        fun block(after: Int): Pair<Int, Int>? {
            if (t.getOrNull(after)?.text != "{") return null
            val close = matching(t, after)
            return if (close < 0) null else after to close
        }
        for ((k, tok) in t.withIndex()) {
            if (tok.kind == 'I' && tok.text == "function") {
                var m = k + 1
                if (t.getOrNull(m)?.text == "*") m++
                val name = t.getOrNull(m)?.takeIf { it.kind == 'I' }?.also { m++ }?.text
                if (t.getOrNull(m)?.text != "(") continue
                val close = matching(t, m)
                val (s, e) = block(close + 1) ?: continue
                result += Fn(name, params(m), t.getOrNull(k - 1)?.text == "async", s, e)
            } else if (tok.kind == 'P' && tok.text == "=>") {
                val async: Boolean
                val ps: Set<String>
                val prev = t.getOrNull(k - 1) ?: continue
                if (prev.text == ")") {
                    var open = k - 1; var d = 0
                    while (open >= 0) { if (t[open].text == ")") d++ else if (t[open].text == "(") { d--; if (d == 0) break }; open-- }
                    if (open < 0) continue
                    ps = params(open); async = t.getOrNull(open - 1)?.text == "async"
                } else if (prev.kind == 'I') { ps = setOf(prev.text); async = t.getOrNull(k - 2)?.text == "async" } else continue
                val (s, e) = block(k + 1) ?: continue
                val name = if (t.getOrNull(k - 1)?.text == ")") null else null
                result += Fn(name, ps, async, s, e)
            } else if (tok.kind == 'P' && tok.text == "(" && k > 0 && t[k - 1].text == "]") {
                val close = matching(t, k)
                val (s, e) = block(close + 1) ?: continue
                result += Fn(null, params(k), false, s, e)
            } else if (tok.kind == 'P' && tok.text == "(" && k > 0) {
                val head = t[k - 1]
                if (head.kind != 'I' || head.text in notFunctionHeads || t.getOrNull(k - 2)?.text == ".") continue
                val close = matching(t, k)
                val (s, e) = block(close + 1) ?: continue
                val async = t.getOrNull(k - 2)?.text == "async"
                result += Fn(head.text, params(k), async, s, e)
            }
        }
        return result
    }

    // ---------- ссылки ----------

    private val keywords = setOf("break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "export", "extends",
        "finally", "for", "function", "if", "import", "in", "instanceof", "new", "return", "super", "switch", "this", "throw", "try", "typeof", "var",
        "void", "while", "with", "yield", "let", "static", "await", "async", "of", "get", "set", "from", "as", "null", "true", "false", "enum", "implements",
        "interface", "package", "private", "protected", "public", "arguments", "target", "meta", "constructor")

    private val globals = ("undefined NaN Infinity globalThis console window document navigator location history localStorage sessionStorage process require module " +
        "exports __dirname __filename Math JSON Object Array String Number Boolean Promise Map Set WeakMap WeakSet WeakRef Symbol Date RegExp Error TypeError " +
        "RangeError SyntaxError ReferenceError EvalError URIError AggregateError BigInt Reflect Proxy Intl Buffer URL URLSearchParams setTimeout clearTimeout " +
        "setInterval clearInterval setImmediate clearImmediate queueMicrotask structuredClone fetch Request Response Headers FormData Blob File FileReader " +
        "parseInt parseFloat isNaN isFinite encodeURIComponent decodeURIComponent encodeURI decodeURI escape unescape eval alert confirm prompt performance " +
        "AbortController AbortSignal TextEncoder TextDecoder Event EventTarget CustomEvent WebSocket Worker Image Audio Node Element HTMLElement Uint8Array " +
        "Int8Array Uint16Array Int16Array Uint32Array Int32Array Float32Array Float64Array BigInt64Array ArrayBuffer DataView Atomics SharedArrayBuffer " +
        "requestAnimationFrame cancelAnimationFrame getComputedStyle matchMedia MutationObserver IntersectionObserver ResizeObserver crypto atob btoa " +
        "describe it test expect beforeEach afterEach beforeAll afterAll jest vi define self top parent frames screen XMLHttpRequest FinalizationRegistry").split(" ").toSet()

    private fun references(t: List<Tok>, add: (DiagnosticKind, String, Int, String, Confidence) -> Unit) {
        val declared = hashSetOf<String>()
        fun collectInside(open: Int) { val close = matching(t, open); if (close > 0) (open + 1 until close).filter { t[it].kind == 'I' }.forEach { declared += t[it].text } }
        for ((k, tok) in t.withIndex()) {
            if (tok.kind == 'I') {
                when (tok.text) {
                    "var", "let", "const" -> {
                        val next = t.getOrNull(k + 1) ?: continue
                        if (next.kind == 'I') declared += next.text else if (next.text == "{" || next.text == "[") collectInside(k + 1)
                        // Остальные объявляемые через запятую: let a = 1, b, c = f(x, y)
                        var m = k + 1
                        var depth = 0
                        while (m < t.size) {
                            val x = t[m]
                            if (x.kind == 'P') {
                                if (x.text in setOf("(", "[", "{")) depth++
                                else if (x.text in setOf(")", "]", "}")) { depth--; if (depth < 0) break }
                                else if (x.text == ";" && depth == 0) break
                                else if (x.text == "," && depth == 0) {
                                    val n2 = t.getOrNull(m + 1)
                                    if (n2?.kind == 'I' && t.getOrNull(m + 2)?.text in setOf("=", ",", ";", "in", "of")) declared += n2.text
                                    else if (n2?.text == "{" || n2?.text == "[") collectInside(m + 1)
                                }
                            }
                            m++
                        }
                    }
                    "function", "class" -> {
                        var m = k + 1
                        if (t.getOrNull(m)?.text == "*") m++
                        t.getOrNull(m)?.takeIf { it.kind == 'I' }?.let { declared += it.text; m++ }
                        if (t.getOrNull(m)?.text == "(") collectInside(m)
                    }
                    "catch" -> if (t.getOrNull(k + 1)?.text == "(") collectInside(k + 1)
                    "import" -> { var m = k + 1; while (m < t.size && t[m].text != "from" && t[m].kind != 'S' && t[m].text != ";") { if (t[m].kind == 'I') declared += t[m].text; m++ } }
                }
                if (t.getOrNull(k + 1)?.text == "=" ) declared += tok.text
                if (t.getOrNull(k + 1)?.text == "=>") declared += tok.text
            } else if (tok.text == "=>" && t.getOrNull(k - 1)?.text == ")") {
                var open = k - 1; var d = 0
                while (open >= 0) { if (t[open].text == ")") d++ else if (t[open].text == "(") { d--; if (d == 0) break }; open-- }
                if (open >= 0) collectInside(open)
            } else if (tok.text == "(" && k > 0 && t[k - 1].kind == 'I' && t[k - 1].text !in notFunctionHeads) {
                val close = matching(t, k)
                if (close > 0 && t.getOrNull(close + 1)?.text == "{") { collectInside(k); declared += t[k - 1].text }
            } else if (tok.text == "(" && k > 0 && t[k - 1].text == "]") {
                val close = matching(t, k)
                if (close > 0 && t.getOrNull(close + 1)?.text == "{") collectInside(k)
            }
        }
        val known = declared + globals
        val candidates = known.filter { it.length >= 3 }
        for ((k, tok) in t.withIndex()) {
            if (tok.kind != 'I' || tok.text in keywords || tok.text in known) continue
            val prev = t.getOrNull(k - 1)?.text
            if (prev == "." || prev == "?.") continue
            if (t.getOrNull(k + 1)?.text == ":") continue
            val hint = closeName(tok.text, candidates, 1)?.takeIf { !it.equals(tok.text, ignoreCase = true) } ?: continue
            add(DiagnosticKind.UNRESOLVED_REFERENCE, "javascript.reference.unresolved", tok.start,
                "Неразрешённая ссылка '${tok.text}'. Возможно, имелось в виду '$hint'.", Confidence.PROVEN)
        }
    }

    // ---------- типы ----------

    private fun literalArithmetic(t: List<Tok>, add: (DiagnosticKind, String, Int, String, Confidence) -> Unit) {
        for ((k, tok) in t.withIndex()) {
            if (tok.kind != 'P' || tok.text !in setOf("-", "*", "/", "%", "**")) continue
            val l = t.getOrNull(k - 1) ?: continue
            // Унарный знак: слева нет значения.
            if (l.kind == 'P' && l.text !in setOf(")", "]", "}")) continue
            if (l.kind == 'I' && l.text in setOf("yield", "return", "case", "typeof", "in", "of", "await", "void", "delete", "new", "throw")) continue
            val r = t.getOrNull(k + 1) ?: continue
            val emptyObject = r.text == "{" && t.getOrNull(k + 2)?.text == "}"
            val emptyArray = r.text == "[" && t.getOrNull(k + 2)?.text == "]"
            if (emptyObject || emptyArray) {
                add(DiagnosticKind.TYPE_MISMATCH, "javascript.type.literal-arithmetic", tok.start,
                    "Арифметическая операция '${tok.text}' применяется к литералу ${if (emptyObject) "объекта" else "массива"}: результат всегда NaN.", Confidence.PROVEN)
            }
        }
    }

    // ---------- равенство ----------

    private fun equality(t: List<Tok>, add: (DiagnosticKind, String, Int, String, Confidence) -> Unit) {
        for ((k, tok) in t.withIndex()) {
            if (tok.kind != 'P' || tok.text !in setOf("==", "===", "!=", "!==")) continue
            val r = t.getOrNull(k + 1)
            val l = t.getOrNull(k - 1)
            if ((r?.kind == 'I' && r.text == "NaN") || (l?.kind == 'I' && l.text == "NaN")) {
                add(DiagnosticKind.FUNCTIONAL_DEFECT, "javascript.defect.nan-comparison", tok.start,
                    "Сравнение с NaN через ${tok.text} всегда ${if (tok.text.startsWith("!")) "истинно" else "ложно"}. Используйте Number.isNaN(x).", Confidence.PROVEN)
                continue
            }
            val rightLiteral = (r?.text == "[" && matching(t, k + 1).let { it > 0 && t.getOrNull(it + 1)?.text !in setOf(".", "[", "(", "?.") }) || (r?.text == "{" && t.getOrNull(k + 2)?.text == "}")
            val leftLiteral = l?.text == "]" && arrayLiteralBefore(t, k - 1) || (l?.text == "}" && t.getOrNull(k - 2)?.text == "{" && t.getOrNull(k - 3)?.text.let { it == "(" || it == "=" || it == "return" })
            if (rightLiteral || leftLiteral) {
                add(DiagnosticKind.FUNCTIONAL_DEFECT, "javascript.defect.array-equality", tok.start,
                    "${tok.text} сравнивает ссылки, а справа новый литерал массива или объекта: результат всегда ${if (tok.text.startsWith("!")) "истинен" else "ложен"}. Сравнивайте длину или содержимое.", Confidence.PROVEN)
            }
        }
    }

    private fun arrayLiteralBefore(t: List<Tok>, close: Int): Boolean {
        var d = 0
        var k = close
        while (k >= 0) {
            if (t[k].text == "]") d++ else if (t[k].text == "[") { d--; if (d == 0) break }
            k--
        }
        if (k < 0) return false
        val before = t.getOrNull(k - 1) ?: return true
        // `a[0] == x` — индексирование, а не литерал.
        if (before.text == "?.") return false
        return !(before.kind == 'I' && before.text !in setOf("return", "typeof", "in", "of", "case") || before.text == ")" || before.text == "]")
    }

    // ---------- дефекты функций ----------

    private fun functionDefects(t: List<Tok>, fn: Fn, add: (DiagnosticKind, String, Int, String, Confidence) -> Unit) {
        var k = fn.bodyStart + 1
        // Вложенные функции анализируются отдельно, но простой обход тела их тоже проходит: ограничимся прямым return.
        while (k < fn.bodyEnd) {
            val tok = t[k]
            if (tok.kind == 'I' && tok.text == "return") {
                val first = t.getOrNull(k + 1)
                val op = t.getOrNull(k + 2)
                val number = t.getOrNull(k + 3)
                if (first != null && first.kind == 'I' && first.text in fn.params && op?.text == "||" && number?.kind == 'N' &&
                    t.getOrNull(k + 4)?.text.let { it == ";" || it == "}" || it == null }) {
                    add(DiagnosticKind.FUNCTIONAL_DEFECT, "javascript.defect.falsy-fallback", op.start,
                        "'${first.text} || ${number.text}' подменяет не только undefined и null, но и допустимые 0, '' и false. Для запасного значения используйте ??.", Confidence.LIKELY)
                }
                if (fn.async && first != null && first.kind == 'I' && first.text !in keywords) {
                    var m = k + 1
                    while (t.getOrNull(m)?.kind == 'I' && t.getOrNull(m + 1)?.text == ".") m += 2
                    if (t.getOrNull(m)?.text == "map" && t.getOrNull(m + 1)?.text == "(") {
                        val close = matching(t, m + 1)
                        val arg = t.getOrNull(m + 2)
                        val callbackIsAsync = arg?.text == "async" || (arg?.kind == 'I' && arg.text in fn.params && t.getOrNull(m + 3)?.text == ")")
                        val statementEnd = t.getOrNull(close + 1)?.text.let { it == ";" || it == "}" || it == null }
                        if (callbackIsAsync && statementEnd) {
                            add(DiagnosticKind.FUNCTIONAL_DEFECT, "javascript.defect.unawaited-map", t[m].start,
                                "async-функция возвращает результат map: это массив промисов, а не значений. Оберните в Promise.all(...) (и await).", Confidence.LIKELY)
                        }
                    }
                }
            }
            k++
        }
    }

    private val numericNames = Regex("(?i)temp|number|num|score|reading|age|price|count|amount|level|degree|rating|weight|height|size|total|value|length")

    private fun sortDefects(t: List<Tok>, functions: List<Fn>, add: (DiagnosticKind, String, Int, String, Confidence) -> Unit) {
        for ((k, tok) in t.withIndex()) {
            if (tok.kind != 'I' || tok.text != "sort" || t.getOrNull(k - 1)?.text != "." || t.getOrNull(k + 1)?.text != "(" || t.getOrNull(k + 2)?.text != ")") continue
            // Контекст: имя ближайшей функции и идентификаторы получателя.
            val enclosing = functions.filter { k in it.bodyStart..it.bodyEnd }.minByOrNull { it.bodyEnd - it.bodyStart }
            val receiver = buildList {
                var m = k - 2
                while (m >= 0 && (t[m].kind == 'I' || t[m].text in setOf(".", "]", "[", ")", "(", "...", ","))) { if (t[m].kind == 'I') add(t[m].text); m-- }
            }
            val hint = (receiver + listOfNotNull(enclosing?.name) + (enclosing?.params ?: emptySet())).any { numericNames.containsMatchIn(it) }
            if (hint) add(DiagnosticKind.FUNCTIONAL_DEFECT, "javascript.defect.default-sort", tok.start,
                "sort() без компаратора сравнивает элементы как строки: числа 10, 2, -3 окажутся в порядке -3, 10, 2. Передайте (a, b) => a - b.", Confidence.LIKELY)
        }
    }
}
