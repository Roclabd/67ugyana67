package ru.codeguard.sast.index

import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtAnnotated
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockStringTemplateEntry
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtCollectionLiteralExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtEscapeStringTemplateEntry
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtSimpleNameStringTemplateEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.KtValueArgument
import ru.codeguard.sast.project.KotlinSource
import ru.codeguard.sast.project.SastProject

/** Функция проекта вместе с файлом и классом-владельцем. */
class FunctionRef(val fn: KtNamedFunction, val file: KotlinSource) {
    val owner: KtClassOrObject? = PsiTreeUtil.getParentOfType(fn, KtClassOrObject::class.java)
    val name: String get() = fn.name ?: "<anonymous>"
    val paramNames: List<String> get() = fn.valueParameters.map { it.name ?: "" }
}

/**
 * Индекс объявлений проекта без разрешения типов: по именам.
 * Достаточно для учебных проектов и вариаций: разрешаем вызовы по имени функции и числу аргументов,
 * а тип получателя — по объявленному типу свойства/параметра конструктора.
 */
class ProjectIndex(val project: SastProject) {
    val functions: List<FunctionRef> = project.kotlin.flatMap { f ->
        PsiTreeUtil.findChildrenOfType(f.psi, KtNamedFunction::class.java).filter { it.name != null && !it.isLocal }
            .map { FunctionRef(it, f) }
    }
    private val functionsByName: Map<String, List<FunctionRef>> = functions.groupBy { it.name }

    /** Объявлена ли в проекте функция с таким именем (иначе вызов уходит во фреймворк/библиотеку). */
    fun declaresFunction(name: String): Boolean = functionsByName.containsKey(name)

    val classes: Map<String, Pair<KtClassOrObject, KotlinSource>> = project.kotlin.flatMap { f ->
        PsiTreeUtil.findChildrenOfType(f.psi, KtClassOrObject::class.java).mapNotNull { c -> c.name?.let { it to (c to f) } }
    }.toMap()

    /** Строковые константы и val с литералом вне функций: имя → значение (только однозначные). */
    private var constants: Map<String, String> = emptyMap()

    init {
        constants = computeConstants()
    }

    private fun computeConstants(): Map<String, String> {
        val all = project.kotlin.flatMap { f ->
            PsiTreeUtil.findChildrenOfType(f.psi, KtProperty::class.java)
                .filter { !it.isLocal && !it.isVar && it.initializer != null }
                .mapNotNull { p -> p.name?.let { n -> n to p.initializer!! } }
        }
        val grouped = all.groupBy({ it.first }, { it.second })
        val out = mutableMapOf<String, String>()
        // Две итерации: константы, ссылающиеся на другие константы.
        repeat(2) {
            for ((name, inits) in grouped) {
                if (name in out) continue
                val values = inits.mapNotNull { stringValue(it, out) }.distinct()
                if (values.size == 1 && inits.size == values.size) out[name] = values.single()
            }
        }
        return out
    }

    fun fileOf(e: PsiElement): KotlinSource? = project.kotlin.firstOrNull { it.psi == e.containingFile }

    /**
     * Кандидаты для вызова: функции проекта с таким именем и подходящим числом параметров.
     * Если известен тип получателя — только функции этого класса (или его реализации интерфейса).
     */
    fun resolveCall(call: KtCallExpression, receiverType: String?): List<FunctionRef> {
        val name = call.calleeExpression?.text ?: return emptyList()
        val argc = call.valueArguments.size
        val byName = functionsByName[name].orEmpty().filter { ref ->
            val params = ref.fn.valueParameters
            val required = params.count { !it.hasDefaultValue() && !it.isVarArg }
            argc >= required && (argc <= params.size || params.any { it.isVarArg })
        }
        if (receiverType == null) return byName
        val exact = byName.filter { it.owner?.name == receiverType }
        if (exact.isNotEmpty()) {
            // Метод без тела (интерфейс/abstract) → реализации и переопределения в проекте.
            // Если реализаций нет (Spring Data репозиторий, MyBatis-маппер) — остаётся объявление.
            if (exact.all { !it.fn.hasBody() }) {
                val subtypes = subtypesOf(receiverType)
                val impls = byName.filter { it.fn.hasBody() && it.owner?.name in subtypes }
                if (impls.isNotEmpty()) return impls
            }
            return exact
        }
        // Метод объявлен в родительском интерфейсе получателя (VehicleRepository : …, VehicleSearchRepository):
        // реализации ищем у наследников того интерфейса, где метод объявлен (Spring Data custom fragment *Impl).
        val supers = supertypesOf(receiverType)
        val inherited = byName.filter { it.owner?.name in supers }
        if (inherited.isNotEmpty()) {
            if (inherited.all { !it.fn.hasBody() }) {
                val declaring = inherited.mapNotNull { it.owner?.name }.toSet()
                val impls = byName.filter { it.fn.hasBody() && it.owner?.name != null && declaring.any { d -> it.owner?.name in subtypesOf(d) } }
                if (impls.isNotEmpty()) return impls
            }
            return inherited
        }
        // Интерфейс → реализации: класс, у которого в супертипах есть receiverType.
        val subtypes = subtypesOf(receiverType)
        return byName.filter { ref -> ref.owner?.name in subtypes }
    }

    private val directSubtypes: Map<String, List<String>> by lazy {
        val out = mutableMapOf<String, MutableList<String>>()
        for ((name, pair) in classes) {
            for (st in pair.first.superTypeListEntries) {
                val base = simpleType(st.typeReference?.text ?: continue)
                out.getOrPut(base) { mutableListOf() } += name
            }
        }
        out
    }

    /** Все родительские типы проекта (транзитивно), без самого типа. */
    private fun supertypesOf(type: String): Set<String> {
        val out = linkedSetOf<String>()
        val queue = ArrayDeque(listOf(type))
        while (queue.isNotEmpty()) {
            val cls = classes[queue.removeFirst()]?.first ?: continue
            for (st in cls.superTypeListEntries) {
                val base = simpleType(st.typeReference?.text ?: continue)
                if (out.add(base)) queue += base
            }
        }
        return out
    }

    /** Все наследники и реализации типа (транзитивно), без самого типа. */
    private fun subtypesOf(type: String): Set<String> {
        val out = linkedSetOf<String>()
        val queue = ArrayDeque(listOf(type))
        while (queue.isNotEmpty()) {
            for (s in directSubtypes[queue.removeFirst()].orEmpty()) if (out.add(s)) queue += s
        }
        return out
    }

    /** Объявленный тип имени в контексте функции: параметр, свойство класса, параметр конструктора. */
    fun declaredType(name: String, context: PsiElement): String? {
        val fn = PsiTreeUtil.getParentOfType(context, KtNamedFunction::class.java, false)
        fn?.valueParameters?.firstOrNull { it.name == name }?.typeReference?.let { return simpleType(it.text) }
        val cls = PsiTreeUtil.getParentOfType(context, KtClassOrObject::class.java) ?: return null
        cls.primaryConstructorParameters.firstOrNull { it.name == name }?.typeReference?.let { return simpleType(it.text) }
        cls.declarations.filterIsInstance<KtProperty>().firstOrNull { it.name == name }?.let { p ->
            p.typeReference?.let { return simpleType(it.text) }
            (p.initializer as? KtCallExpression)?.calleeExpression?.text?.let { return it }
        }
        return null
    }

    /**
     * Значение строкового выражения, если его можно вычислить статически:
     * литералы, шаблоны из констант, конкатенация «+», ссылки на локальные val и константы проекта.
     */
    fun stringValue(expr: KtExpression?, extra: Map<String, String> = emptyMap()): String? {
        return stringValueOf(expr, extra)
    }

    private fun stringValueOf(expr: KtExpression?, extra: Map<String, String>): String? = when (expr) {
        null -> null
        is KtParenthesizedExpression -> stringValue(expr.expression, extra)
        is KtStringTemplateExpression -> templateValue(expr, extra)
        is KtBinaryExpression -> if (expr.operationToken == KtTokens.PLUS) {
            val l = stringValue(expr.left, extra)
            val r = stringValue(expr.right, extra)
            if (l != null && r != null) l + r else null
        } else null
        is KtNameReferenceExpression -> resolveName(expr.getReferencedName(), expr, extra)
        is KtDotQualifiedExpression -> {
            // Companion.CONST, Object.CONST, "…".trimIndent()
            val sel = expr.selectorExpression
            when {
                sel is KtNameReferenceExpression -> resolveName(sel.getReferencedName(), expr, extra)
                sel is KtCallExpression && sel.calleeExpression?.text in setOf("trimIndent", "trimMargin", "trim") ->
                    stringValue(expr.receiverExpression, extra)?.trim()
                else -> null
            }
        }
        else -> null
    }

    private fun templateValue(expr: KtStringTemplateExpression, extra: Map<String, String>): String? {
        val sb = StringBuilder()
        for (e in expr.entries) {
            when (e) {
                is KtLiteralStringTemplateEntry -> sb.append(e.text)
                is KtEscapeStringTemplateEntry -> sb.append(e.unescapedValue)
                is KtSimpleNameStringTemplateEntry -> sb.append(resolveName(e.expression?.text ?: return null, e, extra) ?: return null)
                is KtBlockStringTemplateEntry -> sb.append(stringValue(e.expression, extra) ?: return null)
                else -> return null
            }
        }
        return sb.toString()
    }

    private fun resolveName(name: String, at: PsiElement, extra: Map<String, String>): String? {
        localValInitializer(name, at)?.let { return stringValue(it, extra) }
        return extra[name] ?: constants[name]
    }

    /** Инициализатор локального val с этим именем в объемлющей функции, объявленного до места использования. */
    fun localValInitializer(name: String, at: PsiElement): KtExpression? {
        val fn = PsiTreeUtil.getParentOfType(at, KtNamedFunction::class.java) ?: return null
        return PsiTreeUtil.findChildrenOfType(fn, KtProperty::class.java)
            .filter { it.isLocal && it.name == name && it.textRange.startOffset < at.textRange.startOffset }
            .maxByOrNull { it.textRange.startOffset }?.initializer
    }

    companion object {
        fun simpleType(text: String): String = text.substringBefore('<').removeSuffix("?").substringAfterLast('.').trim()
    }
}

// ───────────── Вспомогательные функции PSI ─────────────

fun KtAnnotated.annotation(vararg names: String): KtAnnotationEntry? =
    annotationEntries.firstOrNull { it.shortName?.asString() in names }

fun KtAnnotated.hasAnnotation(vararg names: String): Boolean = annotation(*names) != null

/** Аргументы аннотации: позиционный первый — под ключом "value". */
fun KtAnnotationEntry.args(): Map<String, KtExpression?> {
    val out = mutableMapOf<String, KtExpression?>()
    valueArguments.forEachIndexed { i, a ->
        val key = a.getArgumentName()?.asName?.asString() ?: if (i == 0) "value" else "arg$i"
        out[key] = a.getArgumentExpression()
    }
    return out
}

/** Строки из выражения аннотации: "x", ["a", "b"], arrayOf("a"). */
fun ProjectIndex.strings(expr: KtExpression?): List<String> = when (expr) {
    null -> emptyList()
    is KtCollectionLiteralExpression -> expr.getInnerExpressions().mapNotNull { stringValue(it) }
    is KtCallExpression -> if (expr.calleeExpression?.text in setOf("arrayOf", "listOf", "setOf"))
        expr.valueArguments.mapNotNull { stringValue(it.getArgumentExpression()) } else emptyList()
    else -> listOfNotNull(stringValue(expr))
}

fun KtCallExpression.argExpr(index: Int, name: String? = null): KtExpression? {
    if (name != null) valueArguments.firstOrNull { it.getArgumentName()?.asName?.asString() == name }?.let { return it.getArgumentExpression() }
    return valueArguments.filter { it.getArgumentName() == null }.getOrNull(index)?.getArgumentExpression()
}

val KtCallExpression.calleeName: String? get() = calleeExpression?.text

/** Получатель вызова: для a.b.foo() — выражение a.b, для foo() — null. */
val KtCallExpression.receiver: KtExpression?
    get() = (parent as? KtDotQualifiedExpression)?.takeIf { it.selectorExpression == this }?.receiverExpression

/** Полное выражение вызова вместе с получателем. */
val KtCallExpression.fullExpression: KtExpression
    get() = (parent as? KtDotQualifiedExpression)?.takeIf { it.selectorExpression == this } ?: this

fun KtValueArgument.expr(): KtExpression? = getArgumentExpression()

/** Нормализованный фрагмент кода для отпечатка: без пробельных различий. */
fun normalizedFragment(e: PsiElement): String = e.text.replace(Regex("\\s+"), " ").trim()

private val LIST_BUILDERS = setOf("arrayOf", "listOf", "setOf", "mutableListOf", "mutableSetOf", "hashSetOf", "linkedSetOf", "arrayListOf", "sequenceOf", "Array")
private val LIST_PASSTHROUGH = setOf("toTypedArray", "toList", "toSet", "asList", "toMutableList", "distinct", "asSequence", "sorted")

/**
 * Строки из массива/списка строк: литерал [..], arrayOf/listOf/setOf (в т. ч. со spread *ARR), ссылка на локальный val
 * или константу/свойство проекта (в т. ч. Obj.NAMES), конкатенация «+», toTypedArray()/toList().
 * null — выражение вычислить статически не удалось; пустой список — массив без строк.
 */
fun ProjectIndex.stringList(expr: KtExpression?, depth: Int = 0): List<String>? {
    if (expr == null || depth > 5) return null
    stringValue(expr)?.let { return listOf(it) }
    return when (expr) {
        is KtParenthesizedExpression -> stringList(expr.expression, depth + 1)
        is KtCollectionLiteralExpression -> expr.getInnerExpressions().flatMap { stringList(it, depth + 1) ?: return null }
        is KtCallExpression -> if (expr.calleeExpression?.text in LIST_BUILDERS)
            expr.valueArguments.flatMap { stringList(it.getArgumentExpression(), depth + 1) ?: return null } else null
        is KtBinaryExpression -> if (expr.operationToken == KtTokens.PLUS) {
            val l = stringList(expr.left, depth + 1)
            val r = stringList(expr.right, depth + 1)
            if (l != null && r != null) l + r else null
        } else null
        is KtNameReferenceExpression -> propertyInitializerNamed(expr.getReferencedName(), expr)?.let { stringList(it, depth + 1) }
        is KtDotQualifiedExpression -> {
            val sel = expr.selectorExpression
            when {
                sel is KtCallExpression && sel.calleeExpression?.text in LIST_PASSTHROUGH -> stringList(expr.receiverExpression, depth + 1)
                sel is KtNameReferenceExpression -> propertyInitializerNamed(sel.getReferencedName(), expr)?.let { stringList(it, depth + 1) }
                else -> null
            }
        }
        else -> null
    }
}

/** Инициализатор val: локальный до места использования, иначе единственное свойство проекта с таким именем. */
fun ProjectIndex.propertyInitializerNamed(name: String, at: PsiElement): KtExpression? {
    localValInitializer(name, at)?.let { return it }
    val props = project.kotlin.flatMap { f -> PsiTreeUtil.findChildrenOfType(f.psi, KtProperty::class.java).filter { !it.isLocal && !it.isVar && it.name == name && it.initializer != null } }
    return props.map { it.initializer!! }.distinctBy { it.text }.singleOrNull()
}
