package workflow.quality

import org.jetbrains.kotlin.KtNodeTypes
import org.jetbrains.kotlin.cli.common.CLIConfigurationKeys
import org.jetbrains.kotlin.cli.common.messages.MessageCollector
import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer
import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.PsiErrorElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.config.CommonConfigurationKeys
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtArrayAccessExpression
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtCallableReferenceExpression
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtForExpression
import org.jetbrains.kotlin.psi.KtImportDirective
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedDeclaration
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectDeclaration
import org.jetbrains.kotlin.psi.KtPackageDirective
import org.jetbrains.kotlin.psi.KtParameter
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtPrefixExpression
import org.jetbrains.kotlin.psi.KtPostfixExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtPsiFactory
import org.jetbrains.kotlin.psi.KtQualifiedExpression
import org.jetbrains.kotlin.psi.KtReturnExpression
import org.jetbrains.kotlin.psi.KtSimpleNameStringTemplateEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.KtTypeReference
import org.jetbrains.kotlin.psi.KtValueArgumentName
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType
import org.jetbrains.kotlin.psi.psiUtil.getStrictParentOfType
import org.springframework.stereotype.Component

/** Разбор Kotlin через PSI — один раз на процесс, как у остальных модулей проекта. */
internal object KotlinPsi {
    private val disposable = Disposer.newDisposable("codeguard-quality")
    private val factory: KtPsiFactory by lazy {
        val config = CompilerConfiguration().apply {
            put(CommonConfigurationKeys.MODULE_NAME, "codeguard-quality")
            put(CLIConfigurationKeys.MESSAGE_COLLECTOR_KEY, MessageCollector.NONE)
        }
        val env = KotlinCoreEnvironment.createForProduction(disposable, config, EnvironmentConfigFiles.JVM_CONFIG_FILES)
        KtPsiFactory(env.project, markGenerated = false)
    }

    fun parse(path: String, text: String): KtFile = synchronized(this) { factory.createFile(path.substringAfterLast('/'), text) }
}

@Component
class KotlinChecker : LanguageChecker {
    override val language = "kotlin"
    override val extensions = setOf("kt")
    override val rules = listOf(
        rule("kotlin.syntax", DiagnosticKind.SYNTAX, "Синтаксис Kotlin", "Ошибки разбора PSI: незакрытые скобки, оборванные выражения, лишние токены."),
        rule("kotlin.type.literal-mismatch", DiagnosticKind.TYPE_MISMATCH, "Литерал не подходит по типу",
            "Литерал присваивается, возвращается или передаётся как аргумент туда, где объявлен несовместимый простой тип."),
        rule("kotlin.reference.unresolved", DiagnosticKind.UNRESOLVED_REFERENCE, "Имя нигде не объявлено",
            "Имя не объявлено в файле, проекте и импортах. Для классов с родителями, лямбд и расширений — только очевидные опечатки."),
        rule("kotlin.defect.int-division-to-double", DiagnosticKind.FUNCTIONAL_DEFECT, "Целочисленное деление до приведения к Double",
            "(a / b).toDouble() при целых a и b теряет дробную часть."),
        rule("kotlin.defect.off-by-one-until-last-index", DiagnosticKind.FUNCTIONAL_DEFECT, "Пропуск последнего элемента в диапазоне",
            "Цикл до lastIndex (или size - 1) смотрит назад на index - 1, поэтому последняя пара не обрабатывается."),
        rule("kotlin.defect.range-inclusive-size", DiagnosticKind.FUNCTIONAL_DEFECT, "Выход за границу: диапазон .. size",
            "Диапазон 0..size включает size, а элемент с таким индексом читается."),
        rule("kotlin.defect.signed-remainder", DiagnosticKind.FUNCTIONAL_DEFECT, "Остаток от деления отрицательной суммы",
            "(a + step) % n возвращает отрицательный результат при отрицательной сумме; нужен Math.floorMod."),
        rule("kotlin.defect.int-overflow-widened-late", DiagnosticKind.FUNCTIONAL_DEFECT, "Переполнение Int до расширения",
            "(a * b).toLong() при Int-операндах умножает в Int и переполняется до приведения."),
        rule("kotlin.defect.blank-fallback", DiagnosticKind.FUNCTIONAL_DEFECT, "Значение по умолчанию не заменяет пустую строку",
            "p ?: \"...\" не покрывает пустые и пробельные строки; нужен isNullOrBlank."),
        rule("kotlin.defect.bigdecimal-equals", DiagnosticKind.FUNCTIONAL_DEFECT, "Сравнение BigDecimal через ==",
            "equals учитывает масштаб: 1.20 и 1.200 не равны. Нужен compareTo."),
        rule("kotlin.defect.month-end-plus-days", DiagnosticKind.FUNCTIONAL_DEFECT, "Конец месяца плюс число дней",
            "К последнему дню месяца прибавляется 28–31 день: следующий месяц имеет другую длину."),
        rule("kotlin.defect.count-with-constant", DiagnosticKind.FUNCTIONAL_DEFECT, "Подсчёт без накопления",
            "В функции подсчёта associateWith { 1 } даёт единицу на ключ вместо числа вхождений."),
        rule("kotlin.defect.quantifier-mismatch", DiagnosticKind.FUNCTIONAL_DEFECT, "Квантор противоречит имени функции",
            "Функция allXxx использует any, либо anyXxx использует all."),
        rule("kotlin.defect.length-for-code-points", DiagnosticKind.FUNCTIONAL_DEFECT, "length вместо числа кодовых точек",
            "В функции подсчёта кодовых точек используется String.length (UTF-16 единицы)."),
        rule("kotlin.defect.tie-break-descending", DiagnosticKind.FUNCTIONAL_DEFECT, "Обратный порядок вторичного строкового ключа",
            "compareByDescending(...).thenByDescending { it.name } упорядочивает равные по убыванию имени."),
        rule("kotlin.defect.write-only-local", DiagnosticKind.FUNCTIONAL_DEFECT, "Локальная коллекция только пишется",
            "Локальный массив или коллекция заполняется, но ни разу не читается: результат вычисления потерян."),
    )

    private fun rule(id: String, kind: DiagnosticKind, title: String, description: String) = QualityRule(id, kind, language, title, description)

    private class FileUnit(val source: SourceUnit, val file: KtFile, val index: LineIndex, val errors: List<PsiErrorElement>)

    override fun check(files: List<SourceUnit>, deadline: Deadline): LanguageResult {
        val diagnostics = mutableListOf<QualityDiagnostic>()
        val skipped = mutableListOf<SkippedFile>()
        val units = mutableListOf<FileUnit>()
        for (source in files) {
            if (deadline.expired) { skipped += SkippedFile(source.path, "Не хватило времени"); continue }
            val psi = KotlinPsi.parse(source.path, source.text)
            val errors = PsiTreeUtil.collectElementsOfType(psi, PsiErrorElement::class.java).toList()
            units += FileUnit(source, psi, LineIndex(source.text), errors)
        }
        val project = ProjectNames.of(units.filter { it.errors.isEmpty() }.map { it.file })
        var analyzed = 0
        for (unit in units) {
            if (deadline.expired) { skipped += SkippedFile(unit.source.path, "Не хватило времени"); continue }
            analyzed++
            if (unit.errors.isNotEmpty()) {
                unit.errors.take(20).forEach { error ->
                    val offset = syntaxOffset(unit, error)
                    diagnostics += QualityDiagnostic(DiagnosticKind.SYNTAX, "kotlin.syntax", language, unit.source.path,
                        unit.index.line(offset), unit.index.column(offset), "Синтаксическая ошибка: ${error.errorDescription}")
                }
                continue
            }
            val context = FileContext(unit.source.path, unit.index, unit.file, project)
            context.run()
            diagnostics += context.found
        }
        return LanguageResult(diagnostics, analyzed, skipped)
    }

    /** Ошибка «в конце файла» относится к последней строке с кодом, а не к пустой строке после неё. */
    private fun syntaxOffset(unit: FileUnit, error: PsiErrorElement): Int {
        val start = error.textRange.startOffset
        val last = unit.index.lastCodeOffset()
        return if (start > last) last + 1 else start
    }

    private class ProjectNames(val topLevel: Set<String>, val packages: Set<String>, val functions: Map<String, List<KtNamedFunction>>) {
        companion object {
            fun of(files: List<KtFile>): ProjectNames {
                val names = hashSetOf<String>()
                val functions = hashMapOf<String, MutableList<KtNamedFunction>>()
                for (file in files) {
                    for (declaration in file.declarations) {
                        declaration.name?.let(names::add)
                        if (declaration is KtNamedFunction && declaration.receiverTypeReference == null) {
                            declaration.name?.let { functions.getOrPut(it) { mutableListOf() }.add(declaration) }
                        }
                        if (declaration is KtObjectDeclaration) {
                            declaration.declarations.forEach { member -> member.name?.let(names::add) }
                        }
                    }
                }
                return ProjectNames(names, files.map { it.packageFqName.asString() }.filter { it.isNotEmpty() }.toSet(), functions)
            }
        }
    }

    private class FileContext(val path: String, val index: LineIndex, val file: KtFile, val project: ProjectNames) {
        val found = mutableListOf<QualityDiagnostic>()
        private val implicitNames = setOf("it", "field", "this", "super", "javaClass", "value", "args", "kotlin", "java")
        private val stdlibNames = setOf("error", "require", "check", "assert", "println", "print", "listOf", "mapOf", "setOf", "run", "with", "apply", "let", "also",
            "repeat", "lazy", "maxOf", "minOf", "arrayOf", "emptyList", "emptyMap", "emptySet", "mutableListOf", "mutableMapOf", "mutableSetOf", "sequenceOf", "to", "TODO")

        private fun report(kind: DiagnosticKind, rule: String, element: PsiElement, message: String, confidence: Confidence = Confidence.PROVEN) {
            val offset = element.textRange.startOffset
            found += QualityDiagnostic(kind, rule, "kotlin", path, index.line(offset), index.column(offset), message, confidence)
        }

        fun run() {
            checkLiteralTypes()
            checkReferences()
            for (function in file.collectDescendantsOfType<KtNamedFunction>()) checkFunctionDefects(function)
            checkChainDefects()
        }

        // ---------- типы ----------

        private fun checkLiteralTypes() {
            for (function in file.collectDescendantsOfType<KtNamedFunction>()) {
                val declared = simpleType(function.typeReference)
                if (declared != null && function.hasDeclaredReturnType()) {
                    val body = function.bodyExpression
                    if (function.hasBlockBody()) {
                        function.collectDescendantsOfType<KtReturnExpression>().forEach { ret ->
                            if (ret.getLabelName() == null && ret.getStrictParentOfType<KtNamedFunction>() == function &&
                                ret.getStrictParentOfType<KtLambdaExpression>()?.let { function.isAncestor(it) } != true) {
                                ret.returnedExpression?.let { mismatch(declared, it, "возвращаемый тип") }
                            }
                        }
                    } else body?.let { mismatch(declared, it, "возвращаемый тип") }
                }
            }
            for (property in file.collectDescendantsOfType<KtProperty>()) {
                val declared = simpleType(property.typeReference) ?: continue
                property.initializer?.let { mismatch(declared, it, "объявленный тип") }
            }
            for (call in file.collectDescendantsOfType<KtCallExpression>()) {
                val name = (call.calleeExpression as? KtNameReferenceExpression)?.getReferencedName() ?: continue
                if (name in stdlibNames) continue
                val candidates = project.functions[name] ?: continue
                if (candidates.size != 1) continue
                val target = candidates.single()
                // Только функция из этого же файла и без одноимённых членов: иначе вызов может относиться к другой перегрузке.
                if (target.containingKtFile !== file || file.collectDescendantsOfType<KtNamedFunction>().count { it.name == name } != 1) continue
                val params = target.valueParameters
                if (params.any { it.isVarArg } || call.lambdaArguments.isNotEmpty() || call.valueArguments.size > params.size) continue
                call.valueArguments.forEachIndexed { i, argument ->
                    if (argument.isNamed() || argument.getSpreadElement() != null) return@forEachIndexed
                    val expected = simpleType(params[i].typeReference) ?: return@forEachIndexed
                    argument.getArgumentExpression()?.let { mismatch(expected, it, "параметр «${params[i].name}» функции $name") }
                }
            }
        }

        private fun KtNamedFunction.isAncestor(element: PsiElement) = PsiTreeUtil.isAncestor(this, element, true)

        private fun mismatch(expected: Pair<String, Boolean>, expression: KtExpression, what: String) {
            val actual = literalType(expression) ?: return
            if (assignable(expected, actual)) return
            val shown = if (expected.second) "${expected.first}?" else expected.first
            val actualShown = if (actual == "null") "null" else "литерал типа '$actual'"
            report(DiagnosticKind.TYPE_MISMATCH, "kotlin.type.literal-mismatch", expression,
                "Несовместимые типы: $what '$shown', найден $actualShown.")
        }

        // ---------- ссылки ----------

        private fun checkReferences() {
            val declared = hashSetOf<String>()
            file.collectDescendantsOfType<KtNamedDeclaration>().forEach { it.name?.let(declared::add) }
            val roots = hashSetOf("java", "javax", "kotlin", "kotlinx", "org", "com", "io", "net", "android", "androidx", "it")
            project.packages.forEach { roots += it.substringBefore('.') }
            var externalStar = false
            for (import in file.importDirectives) {
                val fq = import.importedFqName?.asString() ?: continue
                roots += fq.substringBefore('.')
                if (import.isAllUnder) {
                    if (fq !in project.packages && listOf("kotlin", "java", "javax", "kotlinx.coroutines").none { fq == it || fq.startsWith("$it.") }) externalStar = true
                } else (import.aliasName ?: fq.substringAfterLast('.')).let(declared::add)
            }
            val known = declared + project.topLevel
            val typoCandidates = known.filter { it.length >= 3 }
            for (ref in file.collectDescendantsOfType<KtNameReferenceExpression>()) {
                val name = ref.getReferencedName()
                if (name.isEmpty() || name[0].isUpperCase() || name in implicitNames || name in roots || name in known) continue
                if (!isValueReference(ref)) continue
                val lenient = externalStar || isLenientScope(ref)
                val hint = closeName(name, typoCandidates)?.takeIf { !it.equals(name, ignoreCase = true) && (!lenient || editDistance(name, it) == 1) }
                if (lenient && hint == null) continue
                if (typoCandidates.any { it.equals(name, ignoreCase = true) }) continue
                report(DiagnosticKind.UNRESOLVED_REFERENCE, "kotlin.reference.unresolved", ref,
                    "Неразрешённая ссылка '$name'." + (hint?.let { " Возможно, имелось в виду '$it'." } ?: ""))
            }
        }

        /** Имя в позиции значения: не тип, не вызов, не селектор, не именованный аргумент, не импорт. */
        private fun isValueReference(ref: KtNameReferenceExpression): Boolean {
            val parent = ref.parent
            if (parent is KtCallExpression && parent.calleeExpression == ref) return false
            if (parent is KtQualifiedExpression && parent.selectorExpression == ref) return false
            if (parent is KtValueArgumentName || parent is KtCallableReferenceExpression) return false
            if (ref.getStrictParentOfType<KtTypeReference>() != null) return false
            if (ref.getStrictParentOfType<KtAnnotationEntry>() != null) return false
            if (ref.getStrictParentOfType<KtImportDirective>() != null || ref.getStrictParentOfType<KtPackageDirective>() != null) return false
            if (parent is KtPostfixExpression || parent is KtPrefixExpression) return true
            return true
        }

        private fun isLenientScope(ref: KtNameReferenceExpression): Boolean {
            var node: PsiElement? = ref.parent
            while (node != null && node !is KtFile) {
                when (node) {
                    is KtLambdaExpression -> return true
                    is KtClassOrObject -> if (node.superTypeListEntries.isNotEmpty()) return true
                    is KtNamedFunction -> if (node.receiverTypeReference != null) return true
                    is KtProperty -> if (node.receiverTypeReference != null) return true
                }
                node = node.parent
            }
            return false
        }

        // ---------- функциональные дефекты ----------

        private fun checkFunctionDefects(function: KtNamedFunction) {
            val body = function.bodyExpression ?: return
            val env = environment(function)
            val functionName = function.name.orEmpty()
            for (dot in body.collectDescendantsOfType<KtDotQualifiedExpression>()) {
                val call = dot.selectorExpression as? KtCallExpression ?: continue
                val callee = call.calleeName()
                val receiver = dot.receiverExpression.unwrap()
                // (a / b).toDouble() при целых a и b
                if (callee in setOf("toDouble", "toFloat") && receiver is KtBinaryExpression && receiver.operationToken == KtTokens.DIV) {
                    val left = exactType(receiver.left, env)
                    val right = exactType(receiver.right, env)
                    if (left != null && right != null && isIntegral(left) && isIntegral(right)) {
                        report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.int-division-to-double", receiver,
                            "Целочисленное деление ($left / $right) выполняется до вызова $callee(): дробная часть теряется. Приведите операнд к Double до деления.")
                    }
                }
                // (a * b).toLong() при Int-операндах
                if (callee in setOf("toLong", "toDouble", "toBigInteger") && receiver is KtBinaryExpression && receiver.operationToken == KtTokens.MUL) {
                    if (exactType(receiver.left, env) == "Int" && exactType(receiver.right, env) == "Int" &&
                        (receiver.left?.unwrap() !is KtConstantExpression || receiver.right?.unwrap() !is KtConstantExpression)) {
                        report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.int-overflow-widened-late", receiver,
                            "Произведение двух Int вычисляется в Int и переполняется до вызова $callee(). Расширьте один из множителей до Long заранее.")
                    }
                }
            }
            checkRemainder(function, body, env)
            checkOffByOne(body, env)
            checkBlankFallback(function)
            checkBigDecimalEquality(body, env)
            checkQuantifier(function, body)
            checkCodePoints(function, body, env)
            checkCountWithConstant(function, body)
            checkWriteOnlyLocals(body)
            if (functionName.isEmpty()) return
        }

        private fun checkRemainder(function: KtNamedFunction, body: KtExpression, env: Map<String, String>) {
            val text = function.text
            if (listOf("floorMod", ".mod(", "coerce", "abs(", "< 0", "<0").any { it in text }) return
            for (op in body.collectDescendantsOfType<KtBinaryExpression>()) {
                if (op.operationToken != KtTokens.PERC) continue
                var left = op.left?.unwrap() ?: continue
                while (left is KtDotQualifiedExpression && (left.selectorExpression as? KtCallExpression)?.calleeName() in setOf("toInt", "toLong")) {
                    left = left.receiverExpression.unwrap()
                }
                val sum = left as? KtBinaryExpression ?: continue
                if (sum.operationToken != KtTokens.PLUS) continue
                val divisor = op.right?.unwrap() ?: continue
                if (divisor is KtConstantExpression) continue
                val operands = listOfNotNull(sum.left?.unwrap(), sum.right?.unwrap())
                if (operands.any { it is KtConstantExpression }) continue
                val names = operands.flatMap { it.collectDescendantsOfType<KtNameReferenceExpression>() + listOfNotNull(it as? KtNameReferenceExpression) }.map { it.getReferencedName() }
                val signedHint = names.any { Regex("(?i)step|delta|offset|shift|direction|diff|move|back|rotate|dx|dy").containsMatchIn(it) } ||
                    Regex("(?i)wrap|cursor|circular|cycle|rotate|ring|modulo").containsMatchIn(function.name.orEmpty())
                if (signedHint && env.isNotEmpty()) {
                    report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.signed-remainder", op,
                        "Остаток от деления суммы может быть отрицательным (например, при отрицательном шаге): индекс выйдет за границу. Используйте Math.floorMod или Int.mod.")
                }
            }
        }

        private fun checkOffByOne(body: KtExpression, env: Map<String, String>) {
            for (loop in body.collectDescendantsOfType<KtForExpression>()) {
                val range = loop.loopRange?.unwrap() as? KtBinaryExpression ?: continue
                val variable = loop.loopParameter?.name ?: continue
                val loopBody = loop.body?.text.orEmpty()
                val upper = range.right?.unwrap()
                val operation = range.operationReference.getReferencedName()
                val collection = collectionOfLimit(upper)
                if (operation == "until" && collection != null && collection.second == "last") {
                    val previous = Regex("""\b${Regex.escape(collection.first)}\[\s*${Regex.escape(variable)}\s*-\s*1\s*]""")
                    val next = Regex("""\b${Regex.escape(collection.first)}\[\s*${Regex.escape(variable)}\s*\+\s*1\s*]""")
                    if (previous.containsMatchIn(loopBody) && !next.containsMatchIn(loopBody)) {
                        report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.off-by-one-until-last-index", range,
                            "Диапазон до ${collection.first}.lastIndex не включает последний индекс, а тело читает ${collection.first}[$variable - 1]: последняя пара элементов не обрабатывается. Используйте until ${collection.first}.size.")
                    }
                }
                if (operation == ".." && collection != null && collection.second == "size") {
                    if (Regex("""\b${Regex.escape(collection.first)}\[\s*${Regex.escape(variable)}\s*]""").containsMatchIn(loopBody)) {
                        report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.range-inclusive-size", range,
                            "Диапазон .. включает ${collection.first}.size, а ${collection.first}[$variable] читает элемент с таким индексом: выход за границу. Используйте until или indices.")
                    }
                }
            }
        }

        /** `x.lastIndex`, `x.size - 1` → (x, "last"); `x.size` → (x, "size"). */
        private fun collectionOfLimit(expression: KtExpression?): Pair<String, String>? {
            val e = expression?.unwrap() ?: return null
            if (e is KtDotQualifiedExpression) {
                val receiver = (e.receiverExpression as? KtNameReferenceExpression)?.getReferencedName() ?: return null
                return when ((e.selectorExpression as? KtNameReferenceExpression)?.getReferencedName()) {
                    "lastIndex" -> receiver to "last"
                    "size", "length" -> receiver to "size"
                    else -> null
                }
            }
            if (e is KtBinaryExpression && e.operationToken == KtTokens.MINUS && (e.right as? KtConstantExpression)?.text == "1") {
                val inner = collectionOfLimit(e.left)
                if (inner != null && inner.second == "size") return inner.first to "last"
            }
            return null
        }

        private fun checkBlankFallback(function: KtNamedFunction) {
            val returned = singleReturnedExpression(function)?.unwrap() as? KtBinaryExpression ?: return
            if (returned.operationToken != KtTokens.ELVIS) return
            val left = returned.left as? KtNameReferenceExpression ?: return
            val right = returned.right as? KtStringTemplateExpression ?: return
            val parameter = function.valueParameters.firstOrNull { it.name == left.getReferencedName() } ?: return
            if (parameter.typeReference?.text?.replace(" ", "") != "String?") return
            if (right.text.length <= 2 || right.entries.any { it !is org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry }) return
            report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.blank-fallback", returned,
                "Запасное значение применяется только к null: пустая и пробельная строка '${left.getReferencedName()}' пройдут как есть. Проверьте isNullOrBlank().", Confidence.LIKELY)
        }

        private fun checkBigDecimalEquality(body: KtExpression, env: Map<String, String>) {
            for (op in body.collectDescendantsOfType<KtBinaryExpression>()) {
                if (op.operationToken != KtTokens.EQEQ && op.operationToken != KtTokens.EXCLEQ) continue
                if (isBigDecimal(op.left, env) && isBigDecimal(op.right, env)) {
                    report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.bigdecimal-equals", op,
                        "BigDecimal сравнивается через ${op.operationReference.text}: equals учитывает масштаб, 1.20 и 1.200 считаются разными. Используйте compareTo(...) == 0.")
                }
            }
        }

        private fun isBigDecimal(e: KtExpression?, env: Map<String, String>): Boolean {
            val x = e?.unwrap() ?: return false
            if (x is KtNameReferenceExpression) return env[x.getReferencedName()]?.endsWith("BigDecimal") == true
            if (x is KtDotQualifiedExpression) return (x.selectorExpression as? KtCallExpression)?.calleeName() == "toBigDecimal"
            if (x is KtCallExpression) return x.calleeName() == "BigDecimal"
            return false
        }

        private fun checkQuantifier(function: KtNamedFunction, body: KtExpression) {
            val name = function.name ?: return
            val calls = body.collectDescendantsOfType<KtCallExpression>().mapNotNull { it.calleeName() }.toSet()
            val wantsAll = Regex("^(all|every|are|isAll|hasAll|containsOnly)([A-Z_]|$)").containsMatchIn(name)
            val wantsAny = Regex("^(any|some|hasAny|containsAny)([A-Z_]|$)").containsMatchIn(name)
            if (wantsAll && "any" in calls && "all" !in calls && "none" !in calls) {
                report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.quantifier-mismatch", function.nameIdentifier ?: function,
                    "Имя '$name' обещает «все элементы», а тело использует any: условие выполнится при одном подходящем элементе. Нужен all.", Confidence.LIKELY)
            } else if (wantsAny && "all" in calls && "any" !in calls) {
                report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.quantifier-mismatch", function.nameIdentifier ?: function,
                    "Имя '$name' обещает «хотя бы один», а тело использует all. Нужен any.", Confidence.LIKELY)
            }
        }

        private fun checkCodePoints(function: KtNamedFunction, body: KtExpression, env: Map<String, String>) {
            if (!Regex("(?i)code_?points?|graphem|glyph").containsMatchIn(function.name.orEmpty())) return
            if (Regex("codePoint").containsMatchIn(body.text)) return
            for (dot in body.collectDescendantsOfType<KtDotQualifiedExpression>()) {
                if ((dot.selectorExpression as? KtNameReferenceExpression)?.getReferencedName() == "length") {
                    report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.length-for-code-points", dot,
                        "Функция '${function.name}' считает кодовые точки, но использует length: суррогатная пара (эмодзи, редкие символы) считается за два. Используйте codePointCount(0, length).")
                }
            }
        }

        private fun checkCountWithConstant(function: KtNamedFunction, body: KtExpression) {
            if (!Regex("(?i)count|occurr|tally|freq|histogram|number").containsMatchIn(function.name.orEmpty())) return
            for (call in body.collectDescendantsOfType<KtCallExpression>()) {
                if (call.calleeName() != "associateWith") continue
                val lambda = call.lambdaArguments.firstOrNull()?.getLambdaExpression() ?: continue
                val single = lambda.bodyExpression?.statements?.singleOrNull() as? KtConstantExpression ?: continue
                if (single.text == "1") {
                    report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.count-with-constant", call,
                        "associateWith { 1 } сопоставляет каждому значению единицу, а не число вхождений: повторы теряются. Используйте groupingBy { it }.eachCount().")
                }
            }
        }

        private fun checkChainDefects() {
            for (call in file.collectDescendantsOfType<KtCallExpression>()) {
                when (call.calleeName()) {
                    "plusDays" -> {
                        val dot = call.parent as? KtDotQualifiedExpression ?: continue
                        val days = (call.valueArguments.singleOrNull()?.getArgumentExpression() as? KtConstantExpression)?.text?.toIntOrNull() ?: continue
                        if (days in 28..31 && Regex("lengthOfMonth\\(\\)|atEndOfMonth\\(\\)").containsMatchIn(dot.receiverExpression.text)) {
                            report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.month-end-plus-days", call,
                                "К последнему дню месяца прибавляется $days дн.: длина следующего месяца другая (28–31). Используйте YearMonth.plusMonths(1).atEndOfMonth().")
                        }
                    }
                    "thenByDescending" -> {
                        val dot = call.parent as? KtDotQualifiedExpression ?: continue
                        val lambdaText = call.lambdaArguments.firstOrNull()?.text.orEmpty()
                        if (Regex("""\bit\.(name|title|label|caption|text|key|id)\b""").containsMatchIn(lambdaText) &&
                            dot.receiverExpression.text.contains("ByDescending")) {
                            report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.tie-break-descending", call,
                                "Равные по основному ключу элементы упорядочиваются по убыванию строкового ключа. Если нужен алфавитный порядок, используйте thenBy.", Confidence.LIKELY)
                        }
                    }
                }
            }
        }

        private val mutatingCalls = setOf("add", "addAll", "put", "putAll", "append", "set", "remove", "clear", "fill", "plusAssign", "removeAt", "push")
        private val assignTokens = setOf(KtTokens.EQ, KtTokens.PLUSEQ, KtTokens.MINUSEQ, KtTokens.MULTEQ, KtTokens.DIVEQ, KtTokens.PERCEQ)

        private fun checkWriteOnlyLocals(body: KtExpression) {
            for (local in body.collectDescendantsOfType<KtProperty>()) {
                if (!local.isLocal) continue
                val initializer = local.initializer?.unwrap() as? KtCallExpression ?: continue
                if (initializer.calleeName() !in setOf("IntArray", "LongArray", "DoubleArray", "BooleanArray", "CharArray", "arrayOfNulls", "Array",
                        "mutableListOf", "mutableMapOf", "mutableSetOf", "ArrayList", "HashMap", "HashSet", "LinkedHashMap", "StringBuilder")) continue
                val name = local.name ?: continue
                val scope = local.getStrictParentOfType<KtNamedFunction>() ?: continue
                var writes = 0
                var reads = 0
                for (ref in scope.collectDescendantsOfType<KtNameReferenceExpression>()) {
                    if (ref.getReferencedName() != name || ref.parent === local) continue
                    if (ref.getStrictParentOfType<KtProperty>() == local && ref.parent === local) continue
                    if (isWrite(ref)) writes++ else reads++
                }
                if (writes > 0 && reads == 0) {
                    report(DiagnosticKind.FUNCTIONAL_DEFECT, "kotlin.defect.write-only-local", local.nameIdentifier ?: local,
                        "Локальная переменная '$name' заполняется, но её значение нигде не читается: результат подсчёта потерян, дальше, вероятно, используется не она.")
                }
            }
        }

        private fun isWrite(ref: KtNameReferenceExpression): Boolean {
            val access = ref.parent as? KtArrayAccessExpression
            if (access != null && access.arrayExpression == ref) {
                val parent = access.parent
                if (parent is KtBinaryExpression && parent.left == access && parent.operationToken in assignTokens) return true
                if (parent is KtPostfixExpression || parent is KtPrefixExpression) return true
                return false
            }
            val dot = ref.parent as? KtDotQualifiedExpression
            if (dot != null && dot.receiverExpression == ref) {
                val call = dot.selectorExpression as? KtCallExpression
                // Мутирующий вызов, результат которого не используется.
                if (call != null && call.calleeName() in mutatingCalls) {
                    val holder = dot.parent
                    return holder is org.jetbrains.kotlin.psi.KtBlockExpression || holder is org.jetbrains.kotlin.psi.KtContainerNodeForControlStructureBody ||
                        holder is org.jetbrains.kotlin.psi.KtFunctionLiteral
                }
            }
            return false
        }

        // ---------- вывод простых типов ----------

        private fun environment(function: KtNamedFunction): Map<String, String> {
            val env = hashMapOf<String, String>()
            var scope: PsiElement? = function
            while (scope != null) {
                if (scope is KtNamedFunction) scope.valueParameters.forEach { p -> p.name?.let { n -> p.typeReference?.text?.let { env.putIfAbsent(n, it.replace(" ", "")) } } }
                scope = scope.parent
            }
            function.bodyExpression?.collectDescendantsOfType<KtProperty>()?.forEach { p ->
                val n = p.name ?: return@forEach
                val explicit = p.typeReference?.text?.replace(" ", "")
                val inferred = explicit ?: p.initializer?.let { exactType(it, env) }
                if (inferred != null) env.putIfAbsent(n, inferred)
            }
            function.bodyExpression?.collectDescendantsOfType<KtParameter>()?.forEach { p ->
                val n = p.name ?: return@forEach
                p.typeReference?.text?.let { env.putIfAbsent(n, it.replace(" ", "")) }
            }
            return env
        }

        private val rank = listOf("Byte", "Short", "Int", "Long", "Float", "Double")

        private fun isIntegral(type: String) = type in setOf("Byte", "Short", "Int", "Long")

        private fun exactType(expression: KtExpression?, env: Map<String, String>): String? {
            val e = expression?.unwrap() ?: return null
            literalType(e)?.takeIf { it != "null" }?.let { return it }
            when (e) {
                is KtNameReferenceExpression -> return env[e.getReferencedName()]?.takeIf { it in rank }
                is KtPrefixExpression -> return if (e.operationToken == KtTokens.MINUS || e.operationToken == KtTokens.PLUS) exactType(e.baseExpression, env) else null
                is KtBinaryExpression -> {
                    if (e.operationToken !in setOf(KtTokens.PLUS, KtTokens.MINUS, KtTokens.MUL, KtTokens.DIV, KtTokens.PERC)) return null
                    val l = exactType(e.left, env) ?: return null
                    val r = exactType(e.right, env) ?: return null
                    val best = rank.getOrElse(maxOf(rank.indexOf(l), rank.indexOf(r), rank.indexOf("Int"))) { "Int" }
                    return best
                }
                is KtDotQualifiedExpression -> {
                    val selector = e.selectorExpression
                    val name = when (selector) {
                        is KtCallExpression -> selector.calleeName()
                        is KtNameReferenceExpression -> selector.getReferencedName()
                        else -> null
                    }
                    return when (name) {
                        "size", "length", "lastIndex", "count" -> "Int"
                        "toInt" -> "Int"
                        "toLong" -> "Long"
                        "toShort" -> "Short"
                        "toByte" -> "Byte"
                        "toDouble", "average" -> "Double"
                        "toFloat" -> "Float"
                        "sumOf" -> {
                            val lambda = (selector as? KtCallExpression)?.lambdaArguments?.firstOrNull()?.getLambdaExpression()
                            val inner = lambda?.bodyExpression?.statements?.singleOrNull() as? KtExpression
                            inner?.let { exactType(it, env) }
                        }
                        else -> null
                    }
                }
                else -> return null
            }
        }
    }

    companion object {
        private val simpleTypes = setOf("Int", "Long", "Short", "Byte", "Double", "Float", "Boolean", "String", "Char")

        /** Простой объявленный тип и признак `?`; сложные типы не проверяются. */
        internal fun simpleType(ref: KtTypeReference?): Pair<String, Boolean>? {
            val text = ref?.text?.replace(" ", "") ?: return null
            val nullable = text.endsWith("?")
            val base = text.removeSuffix("?")
            return if (base in simpleTypes) base to nullable else null
        }

        internal fun literalType(expression: KtExpression?): String? {
            val e = expression?.unwrap() ?: return null
            if (e is KtStringTemplateExpression) return "String"
            if (e is KtPrefixExpression && (e.operationToken == KtTokens.MINUS || e.operationToken == KtTokens.PLUS)) {
                return literalType(e.baseExpression)?.takeIf { it in setOf("Int", "Long", "Double", "Float") }
            }
            if (e !is KtConstantExpression) return null
            val text = e.text
            return when (e.node.elementType) {
                KtNodeTypes.INTEGER_CONSTANT -> when {
                    text.endsWith("L") -> "Long"
                    text.endsWith("u") || text.endsWith("U") || text.endsWith("uL") || text.endsWith("UL") -> null
                    else -> "Int"
                }
                KtNodeTypes.FLOAT_CONSTANT -> if (text.endsWith("f") || text.endsWith("F")) "Float" else "Double"
                KtNodeTypes.BOOLEAN_CONSTANT -> "Boolean"
                KtNodeTypes.CHARACTER_CONSTANT -> "Char"
                KtNodeTypes.NULL -> "null"
                else -> null
            }
        }

        internal fun assignable(expected: Pair<String, Boolean>, actual: String): Boolean {
            if (actual == "null") return expected.second
            return when (expected.first) {
                "Int", "Short", "Byte" -> actual == "Int"
                "Long" -> actual == "Int" || actual == "Long"
                "Double" -> actual == "Double"
                "Float" -> actual == "Float"
                else -> actual == expected.first
            }
        }
    }
}

private fun KtExpression.unwrap(): KtExpression {
    var e: KtExpression = this
    while (e is KtParenthesizedExpression) e = e.expression ?: return e
    return e
}

private fun KtCallExpression.calleeName(): String? = (calleeExpression as? KtNameReferenceExpression)?.getReferencedName()

private fun singleReturnedExpression(function: KtNamedFunction): KtExpression? {
    val body = function.bodyExpression ?: return null
    if (!function.hasBlockBody()) return body
    val statement = (body as? org.jetbrains.kotlin.psi.KtBlockExpression)?.statements?.singleOrNull() as? KtReturnExpression
    return statement?.returnedExpression
}

