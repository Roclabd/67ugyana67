package workflow.nodes

import com.fasterxml.jackson.databind.JsonNode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import workflow.engine.*
import java.net.URI
import java.io.IOException
import java.io.OutputStream
import java.nio.file.AccessDeniedException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.DosFileAttributeView
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.HexFormat
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists

class InputRejected(message: String) : IllegalArgumentException(message)

const val UNSUPPORTED_REPOSITORY = "Поддерживаются ссылки на GitHub, GitLab и Bitbucket по https"

fun interface RepositoryAllowlist {
    fun urls(): List<String>
}

private val repositoryUrl = Regex("https://(?:github\\.com/[A-Za-z0-9_.-]+/|gitlab\\.com/(?:[A-Za-z0-9_.-]+/)+|bitbucket\\.org/[A-Za-z0-9_.-]+/)[A-Za-z0-9_.-]+")
private val sha = Regex("[a-f0-9]{40}")
private val branchSegment = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]*")

fun validRepositoryUrl(url: String): Boolean =
    url.length <= 200 && repositoryUrl.matches(url) &&
        url.removePrefix("https://").split('/').none { it in setOf(".", "..", "-") }

/** Нормализованная ссылка: канонический адрес и (для /tree/<ветка>/<путь>) ветка и папка проекта. */
data class RepositoryInput(val url: String, val branch: String? = null, val subdir: String? = null)

private val githubInput = Regex(
    """https://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/(.+?))?/*""")
private val otherInput = Regex("""(https://(?:gitlab\.com|bitbucket\.org)/.+?)(?:\.git)?/*""")

/** Принимает `/`, `.git` и `/tree/<ветка>[/<путь>]` на конце; возвращает канонический https://github.com/owner/repo. */
fun normalizeRepositoryInput(raw: String): RepositoryInput? {
    val text = raw.trim()
    if (text.length > 400 || text.any { it.isWhitespace() || it == '?' || it == '#' }) return null
    githubInput.matchEntire(text)?.let { match ->
        val url = "https://github.com/${match.groupValues[1]}/${match.groupValues[2]}"
        if (!validRepositoryUrl(url)) return null
        val tree = match.groupValues[3].trim('/').split('/').filter(String::isNotEmpty)
        if (tree.isEmpty()) return RepositoryInput(url)
        val branch = tree.first()
        val subdir = tree.drop(1).joinToString("/")
        if (!validBranch(branch) || (subdir.isNotEmpty() && !validSubdir(subdir))) return null
        return RepositoryInput(url, branch, subdir.ifEmpty { null })
    }
    otherInput.matchEntire(text)?.let { match ->
        return if (validRepositoryUrl(match.groupValues[1])) RepositoryInput(match.groupValues[1]) else null
    }
    return null
}

private fun validSubdir(subdir: String) =
    subdir.length <= 300 && subdir.split('/').all { portableSegment.matches(it) && it !in setOf(".", "..") }

private fun validBranch(branch: String): Boolean = branch.length <= 200 && ".." !in branch &&
    branch.split('/').all { branchSegment.matches(it) && !it.endsWith(".") && !it.endsWith(".lock") }

internal fun repositoryRef(params: JsonNode, ciSha: String?): String {
    if (ciSha != null) {
        if (!sha.matches(ciSha)) throw NodeFailure("Некорректный SHA коммита из CI.")
        return ciSha
    }
    val commit = params.path("commitSha").asText().ifEmpty { null }
    val branch = params.path("branch").asText().ifEmpty { null }
    if (commit != null && branch != null) throw NodeFailure("Укажите ветку или SHA коммита.")
    if (commit != null) {
        if (!sha.matches(commit)) throw NodeFailure("Укажите полный SHA коммита из 40 строчных шестнадцатеричных символов.")
        return commit
    }
    if (branch == null) return "HEAD"
    if (!validBranch(branch)) throw NodeFailure("Проверьте имя ветки Git.")
    return "refs/heads/$branch"
}

@Configuration(proxyBeanMethods = false)
class SourceNodes(
    @Value("\${workflow.data-dir:data}") private val data: String,
    private val repositories: RepositoryAllowlist,
) {
    @Bean fun archiveSource(): NodeDefinition = PlatformNode(
        "source.archive", "ZIP-архив", NodeCategory.SOURCE,
        inputs = listOf(PortSpec("trigger", PortType.ANY)),
        outputs = listOf(PortSpec("workspace", PortType.WORKSPACE), PortSpec("revision", PortType.ANY)),
        paramsSchema = schema("""{"type":"object","properties":{"uploadId":{"type":"string","maxLength":36},
            "subdir":{"type":"string","maxLength":300,"title":"Папка проекта в архиве"}},
            "additionalProperties":false}"""),
        description = "Распаковывает загруженный ZIP в рабочую папку запуска.",
    ) { ctx, _ -> withContext(Dispatchers.IO) {
        val source = ctx.trigger.path("source")
        if (!source.isMissingNode && source.path("kind").asText() != "upload") {
            throw NodeFailure("Для этой ноды нужен загруженный ZIP-архив.")
        }
        val id = source.path("uploadId").asText(ctx.params.path("uploadId").asText())
        if (!uploadIdPattern.matches(id)) throw NodeFailure("Укажите идентификатор загруженного ZIP-архива.")
        val upload = Path.of(data).resolve("uploads/$id.zip")
        if (!Files.isRegularFile(upload)) throw NodeFailure("Загруженный ZIP-архив не найден. Загрузите его снова.")
        val target = requireNotNull(ctx.workspace).resolve(ctx.nodeId)
        try {
            SafeArchives.extract(upload, target)
        } catch (_: IOException) {
            throw NodeFailure("Не удалось прочитать ZIP-архив.")
        } catch (_: IllegalArgumentException) {
            throw NodeFailure("ZIP-архив не прошёл проверку: превышены лимиты размера или числа файлов, либо в нём символические ссылки или недопустимые пути.")
        }
        val project = resolveProject(target, ctx.params.path("subdir").asText(), ctx::log)
        val digest = MessageDigest.getInstance("SHA-256")
        DigestInputStream(Files.newInputStream(upload), digest).use { it.transferTo(OutputStream.nullOutputStream()) }
        NodeOutput(mapOf("workspace" to project.path,
            "revision" to mapOf("inputHash" to HexFormat.of().formatHex(digest.digest()), "subdir" to project.subdir)))
    } }

    @Bean fun repositorySource(): NodeDefinition = PlatformNode(
        "source.repo", "Git-репозиторий", NodeCategory.SOURCE,
        inputs = listOf(PortSpec("trigger", PortType.ANY)),
        outputs = listOf(PortSpec("workspace", PortType.WORKSPACE), PortSpec("revision", PortType.ANY)),
        paramsSchema = schema("""{"type":"object","properties":{"url":{"type":"string","maxLength":200},
            "branch":{"type":"string","maxLength":200,"title":"Ветка (пусто - ветка по умолчанию)"},
            "commitSha":{"type":"string","maxLength":40,"title":"Полный SHA коммита"},
            "subdir":{"type":"string","maxLength":300,"title":"Папка проекта в репозитории"}},
            "additionalProperties":false}"""),
        description = "Загружает снимок разрешённого Git-репозитория и фиксирует SHA коммита.",
    ) { ctx, _ -> withContext(Dispatchers.IO) {
        val source = ctx.trigger.path("source")
        if (!source.isMissingNode && source.path("kind").asText() != "repo") {
            throw NodeFailure("Для этой ноды нужна ссылка на Git-репозиторий.")
        }
        val rawUrl = source.path("url").asText(ctx.params.path("url").asText())
        val input = normalizeRepositoryInput(rawUrl)
        val url = input?.url ?: rawUrl
        try {
            validateRepository(url)
        } catch (_: InputRejected) {
            throw NodeFailure(if (input == null) UNSUPPORTED_REPOSITORY
            else "Репозиторий $url не подключён. Создайте проект или сценарий с этой ссылкой.")
        }
        val params = ctx.params.deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>()
        if (input != null) {
            if (input.branch != null && params.path("branch").asText().isEmpty() && params.path("commitSha").asText().isEmpty()) {
                params.put("branch", input.branch)
            }
            if (input.subdir != null && params.path("subdir").asText().isEmpty()) params.put("subdir", input.subdir)
        }
        val ref = repositoryRef(params, ctx.trigger.path("commitSha").asText().ifEmpty { null })
        val root = requireNotNull(ctx.workspace).toAbsolutePath()
        val target = root.resolve(ctx.nodeId)
        val scratch = Files.createTempDirectory(root, "source-")
        try {
            git(scratch, "init", "--bare", ".")
            val host = URI.create(url).host
            val proxy = OutboundProxy.current
            val addresses = try {
                if (proxy == null) PublicNetwork.resolve(host).toList()
                else { OutboundProxy.requireExternalHost(host); emptyList() }
            } catch (_: IOException) {
                throw NodeFailure("Хост Git-репозитория недоступен: не удалось определить его адрес.")
            } catch (_: IllegalArgumentException) {
                throw NodeFailure("Адрес Git-репозитория не публичный: внутренние и локальные адреса запрещены.")
            }
            try {
                git(scratch, *gitNetworkArgs(host, proxy, addresses.map { it.hostAddress }).toTypedArray(),
                    "fetch", "--no-tags", "--no-recurse-submodules", "--depth=1", url, ref)
            } catch (_: IOException) {
                throw NodeFailure("Не удалось подключиться к Git-репозиторию: проверьте сеть и адрес.")
            } catch (_: IllegalArgumentException) {
                throw NodeFailure(fetchFailureMessage(scratch, params))
            }
            val resolved = git(scratch, "rev-parse", "--verify", "FETCH_HEAD^{commit}").trim()
            require(sha.matches(resolved) && (!sha.matches(ref) || resolved == ref))
            val unsupported = git(scratch, "ls-tree", "-r", resolved).lineSequence()
                .filter { it.startsWith("160000 commit ") || it.startsWith("120000 blob ") }.toList()
            if (unsupported.isNotEmpty()) {
                val kind = if (unsupported.any { it.startsWith("120000") }) "символические ссылки" else "подмодули Git"
                val example = unsupported.first().substringAfter('\t').take(80)
                throw NodeFailure("В репозитории есть $kind (например, $example): они не поддерживаются. Удалите их или проверьте другую ветку.")
            }
            // The source tree must not hide files from the analyzer via export attributes.
            val info = Files.createDirectories(scratch.resolve("info"))
            Files.writeString(info.resolve("attributes"), "* -export-ignore -export-subst\n")
            val archive = scratch.resolve("source.zip")
            git(scratch, "archive", "--format=zip", "--output=$archive", resolved)
            try {
                SafeArchives.extract(archive, target)
            } catch (_: IOException) {
                throw NodeFailure("Не удалось распаковать снимок репозитория.")
            } catch (_: IllegalArgumentException) {
                throw NodeFailure("Репозиторий превышает лимиты (размер, число файлов) или содержит недопустимые пути.")
            }
            val project = resolveProject(target, params.path("subdir").asText(), ctx::log)
            NodeOutput(mapOf("workspace" to project.path,
                "revision" to mapOf("commitSha" to resolved, "repoUrl" to url, "subdir" to project.subdir)))
        } finally {
            deleteTree(scratch)
        }
    } }

    fun validateRepository(rawUrl: String) {
        val url = normalizeRepositoryInput(rawUrl)?.url ?: rawUrl
        if (!validRepositoryUrl(url) || url !in repositories.urls()) {
            throw InputRejected(if (normalizeRepositoryInput(rawUrl) == null) UNSUPPORTED_REPOSITORY
                else "Репозиторий не подключён. Создайте проект или сценарий с этой ссылкой.")
        }
    }

    private fun git(directory: Path, vararg args: String): String {
        val transcript = directory.resolve("process.txt")
        val command = ProcessBuilder(listOf("git", "-c", "http.followRedirects=false", "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always", "-c", "credential.helper=", "-c", "http.sslVerify=true",
            "-c", "fetch.fsckObjects=true", "-c", "gc.auto=0", "-c", "init.templateDir=") + args)
            .directory(directory.toFile()).redirectErrorStream(true).redirectOutput(transcript.toFile())
        val env = command.environment()
        env.keys.removeIf { it.startsWith("GIT_", ignoreCase = true) || it.endsWith("_PROXY", ignoreCase = true) }
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = directory.resolve("empty-git-config").toString()
        env["GIT_TERMINAL_PROMPT"] = "0"
        val process = command.start()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        try {
            while (!process.waitFor(100, TimeUnit.MILLISECONDS)) {
                require(System.nanoTime() < deadline && folderBytes(directory) <= SafeArchives.MAX_EXPANDED)
            }
            require(process.exitValue() == 0 && folderBytes(directory) <= SafeArchives.MAX_EXPANDED)
            require(Files.size(transcript) <= 1024 * 1024)
            return Files.readString(transcript)
        } finally {
            if (process.isAlive) {
                process.descendants().forEach { it.destroyForcibly() }
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
            }
        }
    }

    private fun folderBytes(directory: Path): Long {
        var bytes = 0L
        Files.walkFileTree(directory, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                if (attributes.isRegularFile) bytes += attributes.size()
                return FileVisitResult.CONTINUE
            }

            override fun visitFileFailed(file: Path, error: IOException): FileVisitResult {
                // Git renames temporary pack files atomically while fetch is running.
                if (error is NoSuchFileException) return FileVisitResult.CONTINUE
                throw error
            }
        })
        return bytes
    }
}

private fun fetchFailureMessage(scratch: Path, params: JsonNode): String {
    val log = runCatching { Files.readString(scratch.resolve("process.txt")) }.getOrDefault("").lowercase()
    val branch = params.path("branch").asText().ifEmpty { null }
    return when {
        "couldn't find remote ref" in log || "not our ref" in log || "unadvertised object" in log ->
            if (branch != null) "Ветка «$branch» не найдена в репозитории. Проверьте имя ветки или оставьте поле пустым."
            else "Коммит или ветка не найдены в репозитории."
        "not found" in log || "authentication failed" in log || "could not read username" in log ->
            "Репозиторий не найден или закрыт (приватный). Нужен публичный репозиторий."
        else -> "Не удалось загрузить репозиторий: превышено время или лимит размера (до 60 с), либо он недоступен."
    }
}

class ResolvedProject(val path: Path, val subdir: String)

private val projectMarkers = listOf("settings.gradle.kts", "settings.gradle", "build.gradle.kts")
private val skippedDirectories = setOf("node_modules", "build", "out", "target", "dist")

/** Самые неглубокие каталоги с файлами сборки Gradle (глубина до 6). */
internal fun detectProjectDirectories(root: Path): List<Path> {
    var level = listOf(root.toRealPath())
    for (depth in 0..6) {
        val found = level.filter { dir -> projectMarkers.any { Files.isRegularFile(dir.resolve(it), LinkOption.NOFOLLOW_LINKS) } }
        if (found.isNotEmpty()) return found
        if (depth == 6) break
        level = level.flatMap { dir ->
            Files.list(dir).use { entries ->
                entries.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
                    .filter { val name = it.fileName.toString(); !name.startsWith(".") && name !in skippedDirectories }
                    .sorted().toList()
            }
        }
        if (level.isEmpty()) break
    }
    return emptyList()
}

private fun chooseProject(candidates: List<Path>): Path? {
    for (marker in projectMarkers) {
        val matching = candidates.filter { Files.isRegularFile(it.resolve(marker), LinkOption.NOFOLLOW_LINKS) }
        if (matching.size == 1) return matching.single()
        if (matching.size > 1) return null
    }
    return null
}

/**
 * Папка проекта: заданная, если она есть; иначе (пусто или не найдена) - самая неглубокая с settings.gradle(.kts)/build.gradle.kts.
 * Неоднозначность на одной глубине и отсутствие кандидатов при указанной папке - понятная ошибка со списком.
 */
internal fun resolveProject(root: Path, configured: String, log: (String) -> Unit = {}): ResolvedProject {
    val base = root.toRealPath()
    if (configured.isNotEmpty()) {
        val direct = runCatching { snapshotDirectory(root, configured) }.getOrNull()
        if (direct != null) return ResolvedProject(direct, configured)
    }
    val candidates = detectProjectDirectories(base)
    fun names(paths: List<Path>) = paths.take(8).joinToString(", ") { base.relativize(it).toString().replace('\\', '/').ifEmpty { "/" } }
    val prefix = if (configured.isEmpty()) "" else "Папка проекта «$configured» не найдена. "
    if (candidates.isEmpty()) {
        if (configured.isEmpty()) return ResolvedProject(root, "")
        val top = Files.list(base).use { entries ->
            entries.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.sorted().toList()
        }
        throw NodeFailure("${prefix}В репозитории нет settings.gradle(.kts) и build.gradle.kts. Папки верхнего уровня: ${names(top).ifEmpty { "нет" }}. Укажите папку проекта вручную.")
    }
    val chosen = chooseProject(candidates)
        ?: throw NodeFailure("${prefix}Не удалось однозначно определить корень проекта, найдено: ${names(candidates)}. Укажите нужную папку в параметре «Папка проекта».")
    val relative = base.relativize(chosen).toString().replace('\\', '/')
    log("Папка проекта определена автоматически: ${relative.ifEmpty { "корень репозитория" }}")
    return ResolvedProject(if (relative.isEmpty()) root else snapshotDirectory(root, relative), relative)
}

private val uploadIdPattern = Regex("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")

internal fun snapshotDirectory(root: Path, subdir: String): Path {
    if (subdir.isEmpty()) return root
    require(subdir.length <= 300 && subdir.split('/').all { portableSegment.matches(it) && it !in setOf(".", "..") }) {
        "Project directory must be relative to the snapshot"
    }
    val base = root.toRealPath()
    val project = base.resolve(subdir).toRealPath()
    require(project != base && project.startsWith(base) && Files.isDirectory(project))
    // A GitHub ZIP can wrap the repository in a top-level directory.
    for (ancestor in generateSequence(project.parent) { it.parent }.takeWhile { it.startsWith(base) }) {
        for (relative in repositoryAdvisoryPaths) {
            val source = ancestor.resolve(relative)
            val target = project.resolve(relative)
            if (!Files.isDirectory(source.parent, LinkOption.NOFOLLOW_LINKS) ||
                !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) ||
                !Files.notExists(target, LinkOption.NOFOLLOW_LINKS)) continue
            if (!Files.notExists(target.parent, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isDirectory(target.parent, LinkOption.NOFOLLOW_LINKS)) continue
            Files.createDirectories(target.parent)
            Files.copy(source, target)
        }
    }
    return project
}

private val portableSegment = Regex("[A-Za-z0-9_.-]+")
private val repositoryAdvisoryPaths = listOf("vulnerabilities.json", "vulnerability-database/vulnerabilities.json")

/** Сетевые параметры git: через прокси - http.proxy без локального разрешения имени, иначе фиксация проверенных адресов. */
internal fun gitNetworkArgs(host: String, proxy: OutboundProxy.Endpoint?, pinnedAddresses: List<String>): List<String> =
    if (proxy != null) listOf("-c", "http.proxy=${proxy.url}", "-c", "https.proxy=${proxy.url}")
    else listOf("-c", "http.curloptResolve=$host:443:" +
        pinnedAddresses.joinToString(",") { if (':' in it) "[$it]" else it })

fun deleteTree(path: Path) {
    if (!path.exists()) return
    val entries = Files.walk(path).use { paths -> paths.sorted(Comparator.reverseOrder()).toList() }
    for (entry in entries) {
        try {
            Files.deleteIfExists(entry)
        } catch (error: AccessDeniedException) {
            // Git pack objects have the DOS read-only attribute on Windows.
            val attributes = Files.getFileAttributeView(entry, DosFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            if (attributes == null || !attributes.readAttributes().isReadOnly) throw error
            attributes.setReadOnly(false)
            Files.deleteIfExists(entry)
        }
    }
}
