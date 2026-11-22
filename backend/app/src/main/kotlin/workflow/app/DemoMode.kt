package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.filter.OncePerRequestFilter
import workflow.engine.Workflow
import workflow.engine.WorkflowEdge
import workflow.engine.WorkflowNode
import workflow.nodes.normalizeRepositoryInput
import workflow.nodes.validRepositoryUrl
import java.time.Instant
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

const val DEMO_BLOCKED_MESSAGE = "Недоступно в демо-режиме"

class RateLimited(message: String) : RuntimeException(message)

/**
 * Публичный демо-режим (`APP_PUBLIC_DEMO=true`): сервис можно открыть по ссылке или QR-коду без входа.
 * Всё чувствительное только для чтения, запуски идут на заранее разрешённых репозиториях, уведомления отключены,
 * ИИ ограничен по числу запусков в час, запуски ограничены по адресу клиента и глобально.
 * При выключенном режиме (по умолчанию) ни один из методов ничего не меняет.
 */
@Component
class DemoMode(
    @Value("\${APP_PUBLIC_DEMO:false}") val enabled: Boolean,
    @Value("\${APP_PUBLIC_DEMO_REPOS:}") repos: String,
    @Value("\${APP_PUBLIC_DEMO_AI:true}") private val aiEnabled: Boolean,
    @Value("\${APP_PUBLIC_DEMO_AI_PER_HOUR:20}") private val aiPerHour: Int,
    @Value("\${APP_PUBLIC_DEMO_RUNS_PER_HOUR:6}") private val runsPerHour: Int,
    @Value("\${APP_PUBLIC_DEMO_MAX_CONCURRENT:2}") private val maxConcurrent: Int,
    @Value("\${APP_TRUSTED_PROXY:127.0.0.1}") trustedProxy: String,
    @Value("\${APP_ALLOWED_HOSTS:}") allowedHosts: String,
) {
    /** Фиксированный список репозиториев для запусков; пусто - уже подключённые репозитории. */
    val repositories: List<String> = repos.split(',').mapNotNull { normalizeRepositoryInput(it.trim())?.url }
        .filter(::validRepositoryUrl).distinct()
    private val trusted = trustedProxy.split(',').map(String::trim).filter(String::isNotEmpty).toSet()
    private val windows = ConcurrentHashMap<String, ArrayDeque<Instant>>()
    private val aiCalls = ArrayDeque<Instant>()
    private val active = AtomicInteger()

    init {
        if (enabled) require(allowedHosts.isNotBlank()) {
            "В демо-режиме задайте APP_ALLOWED_HOSTS: домен или IP, по которому открывается сайт (и APP_BIND_ADDRESS=0.0.0.0)"
        }
    }

    fun allows(method: String, path: String): Boolean {
        if (!enabled || method in setOf("GET", "HEAD", "OPTIONS")) return true
        if (method != "POST") return false
        return path == "/api/uploads" || path == "/api/workflows/validate" ||
            runPath.matches(path) || copyPath.matches(path)
    }

    fun clientIp(request: HttpServletRequest): String {
        val remote = request.remoteAddr ?: "unknown"
        if (remote !in trusted) return remote
        val chain = request.getHeaders("X-Forwarded-For").toList().flatMap { it.split(',') }.map(String::trim)
            .filter(String::isNotEmpty)
        return chain.lastOrNull { it !in trusted } ?: remote
    }

    /** Занимает место запуска для адреса клиента; `release` вызвать, когда запуск завершён или не начался. */
    fun claimRun(request: HttpServletRequest): () -> Unit {
        if (!enabled) return {}
        takeHourly(clientIp(request), runsPerHour,
            "Слишком много запусков: в демо-режиме не более $runsPerHour в час с одного адреса. Попробуйте позже.")
        if (active.incrementAndGet() > maxConcurrent) {
            active.decrementAndGet()
            throw RateLimited("Демо-сервер занят: одновременно выполняется не более $maxConcurrent проверок. Повторите через минуту.")
        }
        val done = AtomicBoolean()
        return { if (done.compareAndSet(false, true)) active.decrementAndGet() }
    }

    fun claimUpload(request: HttpServletRequest) {
        if (enabled) takeHourly("upload:" + clientIp(request), runsPerHour * 2,
            "Слишком много загрузок: в демо-режиме не более ${runsPerHour * 2} в час с одного адреса.")
    }

    private fun takeHourly(key: String, limit: Int, message: String) {
        if (windows.size > 10_000) {
            val cutoff = Instant.now().minusSeconds(3600)
            windows.entries.removeIf { synchronized(it.value) { it.value.isEmpty() || it.value.last() < cutoff } }
        }
        val window = windows.computeIfAbsent(key) { ArrayDeque() }
        synchronized(window) {
            val cutoff = Instant.now().minusSeconds(3600)
            while (window.isNotEmpty() && window.first() < cutoff) window.removeFirst()
            if (window.size >= limit) throw RateLimited(message)
            window.addLast(Instant.now())
        }
    }

    private fun takeAi(): Boolean {
        if (!aiEnabled) return false
        synchronized(aiCalls) {
            val cutoff = Instant.now().minusSeconds(3600)
            while (aiCalls.isNotEmpty() && aiCalls.first() < cutoff) aiCalls.removeFirst()
            if (aiCalls.size >= aiPerHour) return false
            aiCalls.addLast(Instant.now())
            return true
        }
    }

    fun aiAvailable(): Boolean = aiEnabled && synchronized(aiCalls) {
        val cutoff = Instant.now().minusSeconds(3600)
        aiCalls.count { it >= cutoff } < aiPerHour
    }

    /**
     * Сценарий для запуска в демо: уведомления и ожидание решения (Telegram, почта, вебхук) убираются;
     * ИИ-нода убирается, если ИИ выключен или исчерпан лимит запусков в час (отчёт строится без объяснений).
     */
    fun sanitize(workflow: Workflow): Workflow {
        if (!enabled) return workflow
        val clean = stripNotifications(workflow)
        return if (clean.nodes.any { it.type == "ai.explain" } && !takeAi()) bypassAi(clean) else clean
    }

    fun stripNotifications(workflow: Workflow): Workflow {
        if (!enabled) return workflow
        val removed = workflow.nodes.filter(::outbound).map { it.id }.toSet()
        if (removed.isEmpty()) return workflow
        return workflow.copy(
            nodes = workflow.nodes.filter { it.id !in removed },
            edges = workflow.edges.filter { it.from.node !in removed && it.to.node !in removed },
        )
    }

    private fun outbound(node: WorkflowNode) = node.type.startsWith("notify.") || node.type == REVIEW_WAIT_NODE

    /** Убирает ai.explain, соединяя его вход findings напрямую с потребителями выхода findings. */
    private fun bypassAi(workflow: Workflow): Workflow {
        var edges = workflow.edges
        val ids = workflow.nodes.filter { it.type == "ai.explain" }.map { it.id }
        for (ai in ids) {
            val incoming = edges.filter { it.to.node == ai && it.to.port == "findings" }
            val outgoing = edges.filter { it.from.node == ai && it.from.port == "findings" }
            val bridged = incoming.flatMap { from ->
                outgoing.map { to ->
                    WorkflowEdge("${from.from.node}_${from.from.port}_${to.to.node}_${to.to.port}", from.from, to.to)
                }
            }
            edges = edges.filter { it.from.node != ai && it.to.node != ai } + bridged
        }
        return workflow.copy(nodes = workflow.nodes.filter { it.id !in ids }, edges = edges)
    }

    private companion object {
        val runPath = Regex("/api/workflows/[^/]+/run")
        val copyPath = Regex("/api/templates/[^/]+/copy")
    }
}

@Component
class DemoModeFilter(private val demo: DemoMode, private val json: ObjectMapper) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val path = request.requestURI.trimEnd('/')
        if (!demo.enabled || !path.startsWith("/api") || demo.allows(request.method, path)) {
            chain.doFilter(request, response)
            return
        }
        response.status = HttpServletResponse.SC_FORBIDDEN
        response.contentType = "application/json;charset=UTF-8"
        json.writeValue(response.outputStream, mapOf("code" to "DEMO_READ_ONLY", "message" to DEMO_BLOCKED_MESSAGE))
    }
}

@RestController
@RequestMapping("/api/meta")
class MetaController(private val demo: DemoMode) {
    @GetMapping
    fun get() = mapOf("publicDemo" to demo.enabled, "demoAi" to (demo.enabled && demo.aiAvailable()))
}
