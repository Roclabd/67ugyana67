package ru.codeguard.sast.rules

import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtCallableReferenceExpression
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtImportDirective
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectLiteralExpression
import org.jetbrains.kotlin.psi.KtReturnExpression
import org.jetbrains.kotlin.psi.KtValueArgument
import ru.codeguard.sast.index.calleeName
import ru.codeguard.sast.index.fullExpression
import ru.codeguard.sast.index.normalizedFragment
import ru.codeguard.sast.model.SastClass
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.model.Severity
import ru.codeguard.sast.project.KotlinSource
import ru.codeguard.sast.spring.lambda

/**
 * tls-verification: отключённая проверка TLS.
 *  - HostnameVerifier, который всегда возвращает true (лямбда, SAM-конструктор, object, класс, ссылка на функцию);
 *  - X509TrustManager / X509ExtendedTrustManager с пустым checkServerTrusted (доверие любому сертификату);
 *  - готовые «доверять всему» классы библиотек: NoopHostnameVerifier, TrustAllStrategy, InsecureTrustManagerFactory и т. п.
 * Сообщаем строку проблемного выражения — там, где верификатор создаётся или устанавливается.
 */
class TlsVerificationRule : SastRule {
    override val id = "sast.tls.trust-all"

    private val verifierSetters = setOf("hostnameVerifier", "setHostnameVerifier", "setDefaultHostnameVerifier", "setSSLHostnameVerifier", "sslHostnameVerifier")
    private val insecureNames = setOf(
        "NoopHostnameVerifier", "ALLOW_ALL_HOSTNAME_VERIFIER", "AllowAllHostnameVerifier", "TrustAllStrategy",
        "TrustSelfSignedStrategy", "InsecureTrustManagerFactory",
    )
    private val trustLoaders = setOf("loadTrustMaterial", "setTrustStrategy", "trustStrategy")
    private val broadCatch = setOf("Exception", "Throwable", "CertificateException", "GeneralSecurityException", "RuntimeException")
    private val trustManagerTypes = setOf("X509TrustManager", "X509ExtendedTrustManager", "TrustManager")

    override fun check(ctx: RuleContext) {
        trueConsts = ctx.index.project.kotlin.flatMap { f ->
            PsiTreeUtil.findChildrenOfType(f.psi, org.jetbrains.kotlin.psi.KtProperty::class.java)
                .filter { !it.isLocal && !it.isVar && it.initializer?.text == "true" }.mapNotNull { it.name }
        }.toSet()
        trueFns = emptySet()
        repeat(2) { trueFns = ctx.index.functions.filter { it.fn.valueParameters.size <= 3 && functionBodyAlwaysTrue(it.fn) }.map { it.name }.toSet() }
        // Именованные фабрики «верификатор, принимающий любой хост»: acceptAnyHost() = HostnameVerifier { _, _ -> true }.
        // Если фабрику устанавливают в клиент (.hostnameVerifier(acceptAnyHost())), основное место — установка, функция — в evidence.
        val trustAllFns: Map<String, Pair<KtNamedFunction, KotlinSource>> = ctx.index.functions
            .filter { it.fn.valueParameters.isEmpty() && it.fn.hasBody() }
            .filter { ref -> calls(ref.file).filter { it.calleeName == "HostnameVerifier" && PsiTreeUtil.getParentOfType(it, KtNamedFunction::class.java) == ref.fn }.any { alwaysTrue(it.lambda()) } }
            .associate { it.name to (it.fn to it.file) }
        val installedFns: Set<String> = ctx.index.project.kotlin.flatMap { f -> calls(f).filter { it.calleeName in verifierSetters } }
            .mapNotNull { (it.valueArguments.firstOrNull()?.getArgumentExpression() as? KtCallExpression)?.calleeName }
            .filter { it in trustAllFns }.toSet()
        for (file in ctx.index.project.kotlin) {
            val reportedLines = mutableSetOf<Int>()
            val pending = mutableListOf<Pending>()
            fun report(anchor: PsiElement, what: String, fix: String, extra: PsiElement? = null, foreign: List<ru.codeguard.sast.model.Location> = emptyList()) {
                val stmt = statementOf(anchor)
                val (line, _) = file.rangeOf(stmt)
                if (!reportedLines.add(line)) return
                pending += Pending(stmt, what, fix, anchor is KtClassOrObject || anchor.parent is KtClassOrObject, extra, foreign)
            }

            // 1. SAM-конструктор HostnameVerifier { _, _ -> true }
            for (call in calls(file).filter { it.calleeName == "HostnameVerifier" }) {
                if (alwaysTrue(call.lambda())) {
                    val owner = PsiTreeUtil.getParentOfType(call, KtNamedFunction::class.java)
                    if (owner?.name in installedFns && trustAllFns[owner?.name]?.first == owner) continue // сообщим в месте установки
                    report(call, "HostnameVerifier всегда возвращает true — проверка имени хоста отключена.", HOSTNAME_FIX)
                }
            }
            // 1б. TrustStrategy { _, _ -> true } и loadTrustMaterial(null) { _, _ -> true } / loadTrustMaterial(null, TrustStrategy { … true })
            for (call in calls(file).filter { it.calleeName == "TrustStrategy" }) {
                if (alwaysTrue(call.lambda())) report(call, "TrustStrategy всегда возвращает true — доверяется любая цепочка сертификатов.", TRUST_FIX)
            }
            for (call in calls(file).filter { it.calleeName in trustLoaders }) {
                val lambdas = call.valueArguments.mapNotNull { it.getArgumentExpression() as? KtLambdaExpression } + listOfNotNull(call.lambdaArguments.firstOrNull()?.getLambdaExpression())
                if (lambdas.any { alwaysTrue(it) }) report(call, "Стратегия доверия loadTrustMaterial всегда возвращает true — доверяется любой сертификат.", TRUST_FIX)
            }
            // 1в. System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true") и пустой endpointIdentificationAlgorithm
            for (call in calls(file).filter { it.calleeName == "setProperty" || it.calleeName == "setEndpointIdentificationAlgorithm" }) {
                val a0 = call.valueArguments.getOrNull(0)?.getArgumentExpression()
                val a1 = call.valueArguments.getOrNull(1)?.getArgumentExpression()
                if (call.calleeName == "setProperty" && ctx.index.stringValue(a0) == HTTPCLIENT_NO_HOSTNAME_VERIFY && a1 != null && ctx.index.stringValue(a1)?.lowercase() != "false")
                    report(call, "Системное свойство $HTTPCLIENT_NO_HOSTNAME_VERIFY отключает проверку имени хоста в java.net.http.HttpClient.", HOSTNAME_FIX)
                if (call.calleeName == "setEndpointIdentificationAlgorithm" && emptyAlgorithm(ctx, a0))
                    report(call, "Пустой endpointIdentificationAlgorithm отключает проверку имени хоста в TLS-соединении.", HOSTNAME_FIX)
            }
            for (assign in PsiTreeUtil.findChildrenOfType(file.psi, KtBinaryExpression::class.java).filter { it.operationToken == KtTokens.EQ }) {
                val left = assign.left?.text ?: continue
                if (left.substringAfterLast('.') == "endpointIdentificationAlgorithm" && emptyAlgorithm(ctx, assign.right))
                    report(assign, "Пустой endpointIdentificationAlgorithm отключает проверку имени хоста в TLS-соединении.", HOSTNAME_FIX)
            }
            // 2. .hostnameVerifier { _, _ -> true } / setDefaultHostnameVerifier(…) с лямбдой, ссылкой на функцию или Noop
            for (call in calls(file).filter { it.calleeName in verifierSetters }) {
                val arg = call.lambda() ?: call.valueArguments.firstOrNull()?.getArgumentExpression()
                if (arg is KtLambdaExpression && alwaysTrue(arg)) report(call, "Верификатор имени хоста всегда возвращает true.", HOSTNAME_FIX)
                val factory = (arg as? KtCallExpression)?.calleeName?.let { trustAllFns[it] }
                if (factory != null) {
                    val name = (arg as KtCallExpression).calleeName
                    report(call, "Верификатор имени хоста — функция $name(), всегда возвращающая true.", HOSTNAME_FIX,
                        foreign = listOf(factory.second.loc(factory.first.nameIdentifier ?: factory.first, "функция $name возвращает HostnameVerifier, принимающий любой хост")))
                }
                if (arg is KtCallableReferenceExpression && functionAlwaysTrue(ctx, arg.callableReference.getReferencedName())) {
                    report(call, "Верификатор имени хоста — функция ${arg.callableReference.getReferencedName()}, всегда возвращающая true.", HOSTNAME_FIX)
                }
            }
            // 3. object : HostnameVerifier / X509TrustManager и именованные классы с такими супертипами
            val classes = PsiTreeUtil.findChildrenOfType(file.psi, KtClassOrObject::class.java)
            for (c in classes) {
                val supers = c.superTypeListEntries.mapNotNull { it.typeReference?.text?.substringAfterLast('.') }
                if ("HostnameVerifier" in supers) {
                    val verify = c.declarations.filterIsInstance<KtNamedFunction>().firstOrNull { it.name == "verify" }
                    if (verify != null && functionBodyAlwaysTrue(verify)) report(anchorOf(c), "Реализация HostnameVerifier.verify всегда возвращает true.", HOSTNAME_FIX)
                }
                if ("TrustStrategy" in supers) {
                    val trusted = c.declarations.filterIsInstance<KtNamedFunction>().firstOrNull { it.name == "isTrusted" }
                    if (trusted != null && functionBodyAlwaysTrue(trusted)) report(anchorOf(c), "Реализация TrustStrategy.isTrusted всегда возвращает true.", TRUST_FIX)
                }
                if (supers.any { it in trustManagerTypes }) {
                    val check = c.declarations.filterIsInstance<KtNamedFunction>().firstOrNull { it.name == "checkServerTrusted" }
                    if (check != null && bodyIsEmpty(check)) report(anchorOf(c), "TrustManager с пустым checkServerTrusted принимает любой сертификат.", TRUST_FIX, check)
                }
            }
            // 4. Готовые небезопасные реализации из библиотек
            for (ref in PsiTreeUtil.findChildrenOfType(file.psi, KtNameReferenceExpression::class.java)) {
                if (ref.getReferencedName() !in insecureNames) continue
                if (PsiTreeUtil.getParentOfType(ref, KtImportDirective::class.java) != null) continue
                report(ref, "Используется ${ref.getReferencedName()} — проверка сертификата или имени хоста отключена.", TRUST_FIX)
            }

            emitMerged(ctx, file, pending)

            // Безопасные места: HTTPS-соединения без собственного верификатора (для отчёта о проверенном).
            if (reportedLines.isEmpty()) {
                calls(file).firstOrNull { it.calleeName == "openConnection" && it.fullExpression.parent?.text?.contains("HttpsURLConnection") == true }
                    ?.let { ctx.dismiss(id, file.loc(it), "HTTPS-соединение со стандартной проверкой сертификата и имени хоста") }
            }
        }
    }

    private fun emptyAlgorithm(ctx: RuleContext, e: KtExpression?): Boolean =
        e != null && (e.text == "null" || ctx.index.stringValue(e)?.isEmpty() == true)

    private class Pending(val stmt: PsiElement, val what: String, val fix: String, val classLevel: Boolean, val extra: PsiElement? = null, val foreign: List<ru.codeguard.sast.model.Location> = emptyList())

    private val installers = verifierSetters + trustLoaders + setOf("sslSocketFactory", "setSSLSocketFactory", "setSSLContext", "setSslContext", "sslContext", "setSSLSocketFactory")

    /** Контейнер находки: функция, иначе свойство; null — отдельная находка. */
    private fun containerOf(e: PsiElement): PsiElement? =
        PsiTreeUtil.getParentOfType(e, KtNamedFunction::class.java)
            ?: PsiTreeUtil.getParentOfType(e, org.jetbrains.kotlin.psi.KtProperty::class.java)

    /**
     * Один небезопасный клиент — одна находка: находки внутри одной функции (и объявления класса/object, которые эта функция
     * использует) сводятся к одной. Основная строка — вызов, устанавливающий небезопасный верификатор/стратегию в клиент.
     */
    private fun emitMerged(ctx: RuleContext, file: KotlinSource, pending: List<Pending>) {
        if (pending.isEmpty()) return
        val functions = PsiTreeUtil.findChildrenOfType(file.psi, KtNamedFunction::class.java).toList()
        val groups = linkedMapOf<Any, MutableList<Pending>>()
        for (p in pending) {
            var key: Any? = containerOf(p.stmt)
            if (key == null && p.classLevel) {
                val decl = PsiTreeUtil.getParentOfType(p.stmt, KtClassOrObject::class.java, false)
                val name = decl?.name
                if (name != null) key = functions.firstOrNull { f -> PsiTreeUtil.findChildrenOfType(f, KtNameReferenceExpression::class.java).any { it.getReferencedName() == name } }
            }
            groups.getOrPut(key ?: p) { mutableListOf() } += p
        }
        for ((key, items) in groups) {
            val sorted = items.sortedBy { file.line(it.stmt) }
            var primary: PsiElement = (sorted.firstOrNull { (it.stmt as? KtCallExpression)?.calleeName in installers } ?: sorted.first()).stmt
            if (primary !is KtCallExpression && key is KtNamedFunction && sorted.any { it.classLevel }) {
                PsiTreeUtil.findChildrenOfType(key, KtCallExpression::class.java)
                    .firstOrNull { it.calleeName in installers }?.let { primary = it }
            }
            val first = sorted.firstOrNull { it.stmt === primary } ?: sorted.first()
            // Класс TrustManager без клиента в той же функции: диапазон — от объявления класса до пустого checkServerTrusted,
            // а места установки (SSLContext.init / sslContext(...)) — в evidence.
            val extra = first.extra.takeIf { first.stmt === primary }
            val (line, endLine) = if (extra != null) file.rangeOf(primary, extra) else file.rangeOf(primary)
            val installs = if (extra != null && primary !is KtCallExpression) {
                val clsName = PsiTreeUtil.getParentOfType(primary, KtClassOrObject::class.java, false)?.name
                if (clsName == null) emptyList() else calls(file).filter { c ->
                    (c.calleeName in installers || c.calleeName == "init") &&
                        PsiTreeUtil.findChildrenOfType(c, KtNameReferenceExpression::class.java).any { it.getReferencedName() == clsName } &&
                        PsiTreeUtil.getParentOfType(c, KtClassOrObject::class.java, false)?.name != clsName
                }.map { file.loc(it, "$clsName устанавливается как TrustManager") }
            } else emptyList()
            val evidence = (listOf(file.loc(primary, first.what)) + sorted.map { file.loc(it.stmt, it.what) } + sorted.flatMap { it.foreign } + installs).distinctBy { it.line to it.endLine }
            ctx.findings += SastFinding(
                sastClass = SastClass.TLS_VERIFICATION, rule = id, severity = Severity.MEDIUM,
                path = file.path, line = line, endLine = endLine,
                title = "Отключена проверка TLS",
                description = (if (sorted.size > 1) sorted.joinToString(" ") { it.what } else first.what) +
                    " Соединение примет поддельный сервер, и злоумышленник в сети сможет перехватить или подменить данные.",
                remediation = first.fix,
                evidence = evidence,
                fragment = normalizedFragment(primary),
            )
        }
    }

    private fun calls(file: KotlinSource) = PsiTreeUtil.findChildrenOfType(file.psi, KtCallExpression::class.java)

    /** Для object-литерала — само выражение object : …, для класса — его заголовок. */
    private fun anchorOf(c: KtClassOrObject): PsiElement = PsiTreeUtil.getParentOfType(c, KtObjectLiteralExpression::class.java) ?: c.nameIdentifier ?: c

    /** Расширяем до присваивания/аргумента, если выражение — его правая часть (hostnameVerifier = …). */
    private fun statementOf(e: PsiElement): PsiElement {
        val p = e.parent
        if (p is KtBinaryExpression && p.operationToken == KtTokens.EQ) return p
        if (p is KtValueArgument) PsiTreeUtil.getParentOfType(p, KtCallExpression::class.java)?.let { return it }
        // Ссылка на «небезопасный» класс: NoopHostnameVerifier.INSTANCE, NoopHostnameVerifier()
        if (e is KtNameReferenceExpression) {
            val q = e.parent
            if (q is org.jetbrains.kotlin.psi.KtDotQualifiedExpression && q.receiverExpression == e) return q
            if (q is KtCallExpression) return q
        }
        return e
    }

    /**
     * Лямбда всегда возвращает true: последнее выражение — true, других результатов нет
     * (ни false, ни return с иным значением, ни вызова настоящей проверки). Логирование перед true не спасает.
     */
    private fun alwaysTrue(lambda: KtLambdaExpression?): Boolean {
        val body = lambda?.bodyExpression ?: return false
        return endsWithTrueOnly(body.statements, body)
    }

    private fun endsWithTrueOnly(stmts: List<KtExpression>, body: PsiElement): Boolean {
        if (stmts.isEmpty() || !isTrue(stmts.last())) return false
        if (PsiTreeUtil.findChildrenOfType(body, KtConstantExpression::class.java).any { it.text == "false" }) return false
        if (PsiTreeUtil.findChildrenOfType(body, KtReturnExpression::class.java).any { !isTrue(it.returnedExpression) }) return false
        return PsiTreeUtil.findChildrenOfType(body, KtCallExpression::class.java).none { it.calleeName in VERIFYING_CALLS }
    }

    private var trueConsts: Set<String> = emptySet()
    private var trueFns: Set<String> = emptySet()

    private fun isTrue(e: KtExpression?): Boolean = when (e) {
        is KtConstantExpression -> e.text == "true"
        is KtReturnExpression -> isTrue(e.returnedExpression)
        is KtNameReferenceExpression -> e.getReferencedName() in trueConsts
        is org.jetbrains.kotlin.psi.KtDotQualifiedExpression -> e.receiverExpression is KtNameReferenceExpression && isTrue(e.selectorExpression)
        is KtCallExpression -> e.calleeName in trueFns
        else -> false
    }

    private fun functionBodyAlwaysTrue(fn: KtNamedFunction): Boolean {
        val body = fn.bodyExpression ?: return false
        if (body !is KtBlockExpression) return isTrue(body)
        return endsWithTrueOnly(body.statements, body)
    }

    private fun functionAlwaysTrue(ctx: RuleContext, name: String): Boolean =
        ctx.index.functions.any { it.name == name && it.fn.valueParameters.size == 2 && functionBodyAlwaysTrue(it.fn) }

    /**
     * checkServerTrusted ничего не проверяет: нет throw и нет вызова проверки (делегат checkServerTrusted,
     * checkValidity, verify, validate…). Пустое тело, return, логирование — всё это «доверять любому сертификату».
     */
    private fun bodyIsEmpty(fn: KtNamedFunction): Boolean {
        val body = fn.bodyExpression ?: return false
        // throw и проверяющие вызовы внутри try, чьё исключение молча проглатывается, ничего не проверяют
        val throws = PsiTreeUtil.findChildrenOfType(body, org.jetbrains.kotlin.psi.KtThrowExpression::class.java).filter { !swallowed(it, body) }
        if (throws.isNotEmpty()) return false
        val calls = PsiTreeUtil.findChildrenOfType(body, KtCallExpression::class.java).filter { !swallowed(it, body) } + listOfNotNull((body as? KtCallExpression))
        return calls.none { c -> c.calleeName in VERIFYING_CALLS || c.calleeName?.contains(Regex("(?i)valid|verify|check")) == true }
    }

    /** Элемент лежит в try-блоке, все catch которого широкие (Exception, Throwable, CertificateException…) и не пробрасывают исключение. */
    private fun swallowed(e: PsiElement, root: PsiElement): Boolean {
        var cur: PsiElement? = e
        while (cur != null && cur != root) {
            val p = cur.parent
            if (p is org.jetbrains.kotlin.psi.KtTryExpression && cur == p.tryBlock) {
                val catches = p.catchClauses
                if (catches.isNotEmpty() && catches.all { c ->
                        (c.catchParameter?.typeReference?.text?.substringAfterLast('.')?.removeSuffix("?") in broadCatch) &&
                            PsiTreeUtil.findChildrenOfType(c.catchBody, org.jetbrains.kotlin.psi.KtThrowExpression::class.java).isEmpty()
                    }) return true
            }
            cur = p
        }
        return false
    }

    companion object {
        /** Вызовы, которые выполняют настоящую проверку: делегирование штатному верификатору/TrustManager. */
        val VERIFYING_CALLS = setOf("verify", "checkServerTrusted", "checkValidity", "validate", "getDefaultHostnameVerifier")

        const val HTTPCLIENT_NO_HOSTNAME_VERIFY = "jdk.internal.httpclient.disableHostnameVerification"
        const val HOSTNAME_FIX = "Удалить собственный HostnameVerifier и использовать штатную проверку имени хоста; для тестовых стендов — корректный сертификат на нужное имя."
        const val TRUST_FIX = "Использовать штатный TrustManager и проверку имени хоста; доверенный сертификат добавлять в отдельное хранилище доверия, а не отключать проверку."
    }
}
