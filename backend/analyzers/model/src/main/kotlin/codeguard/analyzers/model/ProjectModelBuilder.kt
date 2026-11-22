package codeguard.analyzers.model

import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer
import org.jetbrains.kotlin.com.intellij.psi.PsiErrorElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.psi.KtElement
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtPsiFactory
import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.HexFormat

/** Owns the PSI environment. Keep open for the lifetime of any returned model. */
class ProjectModelBuilder : AutoCloseable {
    private val disposable = Disposer.newDisposable()
    private val environment = KotlinCoreEnvironment.createForProduction(
        disposable, CompilerConfiguration(), EnvironmentConfigFiles.JVM_CONFIG_FILES,
    )
    private val factory = KtPsiFactory(environment.project, markGenerated = false)
    private var closed = false

    @Synchronized
    fun build(workspace: Path): ProjectModelResult {
        check(!closed) { "Project model builder is closed" }
        val root = try {
            workspace.toRealPath(LinkOption.NOFOLLOW_LINKS)
        } catch (_: IOException) {
            return failed()
        }
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return failed()

        val errors = mutableListOf<ParseError>()
        val ignored = mutableListOf<String>()
        val files = try {
            collectFiles(root, errors, ignored)
        } catch (_: IOException) {
            return failed()
        }
        val kotlin = linkedMapOf<String, KtFile>()
        for (source in files) {
            checkInterrupted()
            if (source.type != SourceType.KOTLIN && source.type != SourceType.KOTLIN_SCRIPT) continue
            val psi = factory.createFile(source.path.substringAfterLast('/'), source.text)
            val syntaxErrors = PsiTreeUtil.findChildrenOfType(psi, PsiErrorElement::class.java)
            if (syntaxErrors.isEmpty()) {
                kotlin[source.path] = psi
            } else {
                syntaxErrors.map { source.lineAt(it.textRange.startOffset) }.distinct().forEach { line ->
                    errors += ParseError(source.path, line, "Ошибка синтаксиса Kotlin")
                }
            }
        }
        val (declarations, calls) = indexKotlin(files, kotlin)
        val catalogs = parseVersionCatalogs(files, errors)
        val model = ProjectModel(
            root = root,
            files = files,
            kotlin = kotlin.toMap(),
            declarations = declarations,
            calls = calls,
            config = parseConfig(files, catalogs, errors),
            gradle = parseGradle(files, kotlin, catalogs, errors),
            spring = parseSpring(files, kotlin),
            sqlSchema = parseSqlSchema(files, kotlin, errors),
            parseErrors = errors.distinct().sortedWith(compareBy(ParseError::path, ParseError::line, ParseError::message)),
            languages = languageUsage(files),
            ignoredDirectories = ignored.sorted(),
        )
        val status = if (model.parseErrors.isEmpty()) ModelStatus.COMPLETE else ModelStatus.PARTIAL
        return ProjectModelResult(model, ModelSummary(status, files.size, model.parseErrors.size))
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            Disposer.dispose(disposable)
        }
    }

    private fun failed() = ProjectModelResult(null, ModelSummary(ModelStatus.FAILED, 0, 0))
}

internal fun checkInterrupted() {
    if (Thread.currentThread().isInterrupted) throw InterruptedException("Разбор проекта прерван")
}

private val metadataDirectories = setOf(
    ".git", ".gradle", ".idea", "node_modules", "vendor", "dist", ".venv", "venv", "__pycache__", ".next", ".nuxt",
    "Pods", ".terraform", ".tox", ".mypy_cache", ".pytest_cache", "bower_components", ".svn", ".hg", ".dart_tool",
)
private val generatedDirectories = setOf("build", "target")
private const val MAX_FILES = 20_000
private const val MAX_SOURCE_BYTES = 1_000_000L
private const val WALK_BUDGET_NANOS = 60_000_000_000L

private fun collectFiles(root: Path, errors: MutableList<ParseError>, ignored: MutableList<String>): List<SourceFile> {
    val files = mutableListOf<SourceFile>()
    val deadline = System.nanoTime() + WALK_BUDGET_NANOS
    val realRoot = root.toRealPath()
    fun relative(path: Path) = root.relativize(path).joinToString("/")

    Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
            if (dir != root) {
                val name = dir.fileName.toString()
                val generated = name in generatedDirectories && root.relativize(dir).none { it.toString() == "src" }
                if (generated || name in metadataDirectories) {
                    ignored += relative(dir)
                    return FileVisitResult.SKIP_SUBTREE
                }
            }
            checkInterrupted()
            val realDirectory = try {
                dir.toRealPath()
            } catch (error: IOException) {
                if (dir == root) throw error
                errors += ParseError(relative(dir), null, "Не удалось прочитать каталог")
                return FileVisitResult.SKIP_SUBTREE
            }
            if (!realDirectory.startsWith(realRoot)) {
                errors += ParseError(relative(dir), null, "Каталог вне снимка проекта")
                return FileVisitResult.SKIP_SUBTREE
            }
            return FileVisitResult.CONTINUE
        }

        override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
            val path = relative(file)
            if (!attrs.isRegularFile) {
                errors += ParseError(path, null, "Неподдерживаемый тип файла")
                return FileVisitResult.CONTINUE
            }
            checkInterrupted()
            if (files.size >= MAX_FILES || System.nanoTime() > deadline) {
                errors += ParseError(".", null, if (files.size >= MAX_FILES)
                    "Достигнут лимит $MAX_FILES файлов: остальные файлы не проверялись"
                else "Превышено время обхода проекта: остальные файлы не проверялись")
                return FileVisitResult.TERMINATE
            }
            val foreign = isForeignText(path) && sourceType(file.fileName.toString()) == SourceType.OTHER
            var type = sourceType(file.fileName.toString()).let {
                if (it == SourceType.JSON && attrs.size() > MAX_JSON_BYTES) SourceType.OTHER else it
            }
            val oversized = attrs.size() > MAX_SOURCE_BYTES && type != SourceType.OTHER && type != SourceType.ADVISORY_DATABASE
            if (oversized || (foreign && attrs.size() > MAX_SOURCE_BYTES)) {
                errors += ParseError(path, null, "Файл больше 1 МБ: не анализировался")
                type = SourceType.OTHER
            }
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                val text = DigestInputStream(Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS), digest).use { stream ->
                    if (type == SourceType.OTHER) {
                        // Текстовые скрипты и конфигурации (.sh, .conf, .ini, .txt, .http) читаем для поиска секретов; остальное — только хеш.
                        val readable = (foreign || file.fileName.toString().substringAfterLast('.', "").lowercase() in otherTextExtensions) &&
                            attrs.size() <= MAX_OTHER_TEXT_BYTES
                        val bytes = if (readable) stream.readAllBytes() else {
                            stream.transferTo(OutputStream.nullOutputStream())
                            null
                        }
                        bytes?.let {
                            try {
                                // Исходники на других языках бывают в Latin-1/CP1251: читаем с заменой, секрет ASCII не теряется.
                                val decoded = decodeSourceText(it)
                                decoded.removePrefix("﻿").replace("\r\n", "\n").replace('\r', '\n')
                            } catch (_: java.nio.charset.CharacterCodingException) {
                                ""
                            }
                        } ?: ""
                    } else {
                        decodeSourceText(stream.readAllBytes()).replace("\r\n", "\n").replace('\r', '\n')
                    }
                }
                val hash = HexFormat.of().formatHex(digest.digest())
                files += SourceFile(path, type, text, hash)
            } catch (_: IOException) {
                errors += ParseError(path, null, "Не удалось прочитать файл в UTF-8")
            }
            return FileVisitResult.CONTINUE
        }

        override fun visitFileFailed(file: Path, exc: IOException): FileVisitResult {
            if (file == root) throw exc
            errors += ParseError(relative(file), null, "Не удалось прочитать файл")
            return FileVisitResult.CONTINUE
        }

        override fun postVisitDirectory(dir: Path, exc: IOException?): FileVisitResult {
            if (exc != null) {
                if (dir == root) throw exc
                errors += ParseError(relative(dir), null, "Не удалось прочитать каталог")
            }
            return FileVisitResult.CONTINUE
        }
    })
    return files.sortedBy(SourceFile::path)
}

private const val MAX_JSON_BYTES = 1_000_000L
private const val MAX_OTHER_TEXT_BYTES = 1_000_000L
internal val otherTextExtensions = setOf("sh", "bash", "conf", "ini", "cfg", "txt", "http", "rest")
private val lockJsonNames = setOf("package-lock.json", "npm-shrinkwrap.json")

private fun sourceType(name: String): SourceType {
    val extension = name.substringAfterLast('.', "").lowercase()
    return when {
        name == ".env" || name.startsWith(".env.") -> SourceType.ENV
        name == "gradle.lockfile" -> SourceType.LOCKFILE
        name == "vulnerabilities.json" -> SourceType.ADVISORY_DATABASE
        name.equals("Dockerfile", true) || name.startsWith("Dockerfile.") || extension == "dockerfile" -> SourceType.DOCKERFILE
        name.lowercase() in lockJsonNames -> SourceType.OTHER
        else -> when (extension) {
            "kt" -> SourceType.KOTLIN
            "kts" -> SourceType.KOTLIN_SCRIPT
            "yaml", "yml" -> SourceType.YAML
            "properties" -> SourceType.PROPERTIES
            "sql" -> SourceType.SQL
            "toml" -> SourceType.TOML
            "md", "markdown" -> SourceType.MARKDOWN
            "xml" -> SourceType.XML
            "pem", "key" -> SourceType.PEM
            "env" -> SourceType.ENV
            "json" -> SourceType.JSON
            else -> SourceType.OTHER
        }
    }
}

internal fun KtElement.psiLocation(source: SourceFile): Location = source.location(textRange.startOffset)

/**
 * Текст файла проекта в любой распространённой кодировке: UTF-8 (с BOM и без), UTF-16 по BOM,
 * иначе Windows-1251 (русские комментарии в старых проектах). Бинарный файл (нулевые байты) — пустой текст, не ошибка.
 */
internal fun decodeSourceText(bytes: ByteArray): String {
    if (bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte())
        return String(bytes, 3, bytes.size - 3, Charsets.UTF_8)
    if (bytes.size >= 2 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xFE.toByte())
        return String(bytes, 2, bytes.size - 2, Charsets.UTF_16LE)
    if (bytes.size >= 2 && bytes[0] == 0xFE.toByte() && bytes[1] == 0xFF.toByte())
        return String(bytes, 2, bytes.size - 2, Charsets.UTF_16BE)
    val sample = bytes.size.coerceAtMost(8192)
    if ((0 until sample).count { bytes[it] == 0.toByte() } > 0) return ""
    return try {
        Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString()
    } catch (_: java.nio.charset.CharacterCodingException) {
        String(bytes, java.nio.charset.Charset.forName("windows-1251"))
    }
}
