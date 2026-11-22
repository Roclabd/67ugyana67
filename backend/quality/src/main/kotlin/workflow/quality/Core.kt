package workflow.quality

import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes

/** Вид диагностики. Ровно четыре, как в постановке. */
enum class DiagnosticKind(val code: String, val title: String) {
    SYNTAX("syntax", "Ошибка синтаксиса"),
    TYPE_MISMATCH("type-mismatch", "Несовместимые типы"),
    UNRESOLVED_REFERENCE("unresolved-reference", "Неразрешённая ссылка"),
    FUNCTIONAL_DEFECT("functional-defect", "Функциональный дефект"),
}

/** PROVEN — дефект следует из текста; LIKELY — эвристика по имени или форме кода, нужен взгляд человека. */
enum class Confidence { PROVEN, LIKELY }

data class QualityRule(val id: String, val kind: DiagnosticKind, val language: String, val title: String, val description: String)

data class QualityDiagnostic(
    val kind: DiagnosticKind,
    val rule: String,
    val language: String,
    val path: String,
    val line: Int,
    val column: Int,
    val message: String,
    val confidence: Confidence = Confidence.PROVEN,
)

class SourceUnit(val path: String, val text: String) {
    val extension: String get() = path.substringAfterLast('.', "").lowercase()
}

data class SkippedFile(val path: String, val reason: String)

data class LanguageResult(
    val diagnostics: List<QualityDiagnostic>,
    val analyzed: Int,
    val skipped: List<SkippedFile> = emptyList(),
)

/** Крайний срок проверки. После него проверяющие прекращают работу и возвращают то, что успели. */
class Deadline(private val nanos: Long) {
    val expired: Boolean get() = System.nanoTime() > nanos
    companion object { fun afterMillis(ms: Long) = Deadline(System.nanoTime() + ms * 1_000_000) }
}

/**
 * Точка расширения: один проверяющий на язык. Новый язык подключается бином Spring, реализующим этот интерфейс;
 * движок, нода и API не меняются.
 */
interface LanguageChecker {
    val language: String
    val extensions: Set<String>
    val rules: List<QualityRule>
    fun check(files: List<SourceUnit>, deadline: Deadline): LanguageResult
}

data class QualityOptions(
    val kinds: Set<DiagnosticKind> = DiagnosticKind.entries.toSet(),
    val languages: Set<String>? = null,
    val timeoutMillis: Long = 30_000,
    val maxDiagnostics: Int = 500,
)

enum class QualityStatus { OK, ISSUES, PARTIAL, TIMEOUT, NOT_APPLICABLE, ERROR }

data class QualityReport(
    val status: QualityStatus,
    val diagnostics: List<QualityDiagnostic>,
    val truncated: Boolean,
    val filesAnalyzed: Int,
    val filesByLanguage: Map<String, Int>,
    val skipped: List<SkippedFile>,
    val unsupported: List<String>,
    val rules: List<QualityRule>,
    val durationMs: Long,
    val message: String,
)

class QualityEngine(private val checkers: List<LanguageChecker>) {
    val rules: List<QualityRule> get() = checkers.flatMap { it.rules }
    val languages: List<String> get() = checkers.map { it.language }

    fun run(workspace: Path, options: QualityOptions = QualityOptions()): QualityReport {
        val started = System.nanoTime()
        val deadline = Deadline.afterMillis(options.timeoutMillis)
        val active = checkers.filter { options.languages == null || it.language in options.languages }
        val scan = try {
            WorkspaceScanner.scan(workspace, active.flatMap { it.extensions }.toSet(), deadline)
        } catch (error: Exception) {
            return report(QualityStatus.ERROR, emptyList(), false, 0, emptyMap(), emptyList(), emptyList(), active, started,
                "Не удалось прочитать рабочую папку проверки.")
        }
        val diagnostics = mutableListOf<QualityDiagnostic>()
        val skipped = scan.skipped.toMutableList()
        val byLanguage = linkedMapOf<String, Int>()
        var analyzed = 0
        var timedOut = scan.timedOut
        for (checker in active) {
            val files = scan.files.filter { it.extension in checker.extensions }
            if (files.isEmpty()) continue
            if (deadline.expired) { timedOut = true; skipped += files.map { SkippedFile(it.path, "Не хватило времени") }; continue }
            val result = try {
                checker.check(files, deadline)
            } catch (error: Exception) {
                skipped += files.map { SkippedFile(it.path, "Внутренняя ошибка проверки ${checker.language}") }
                continue
            }
            diagnostics += result.diagnostics.filter { it.kind in options.kinds }
            skipped += result.skipped
            analyzed += result.analyzed
            byLanguage[checker.language] = result.analyzed
            if (deadline.expired) timedOut = true
        }
        val sorted = diagnostics.distinct().sortedWith(compareBy({ it.path }, { it.line }, { it.column }, { it.rule }))
        val truncated = sorted.size > options.maxDiagnostics
        val shown = sorted.take(options.maxDiagnostics)
        val status = when {
            timedOut -> QualityStatus.TIMEOUT
            analyzed == 0 && skipped.isEmpty() -> QualityStatus.NOT_APPLICABLE
            skipped.isNotEmpty() -> QualityStatus.PARTIAL
            shown.isNotEmpty() -> QualityStatus.ISSUES
            else -> QualityStatus.OK
        }
        val message = when (status) {
            QualityStatus.NOT_APPLICABLE -> "В проекте нет файлов .kt, .py, .js, .mjs, .cjs."
            QualityStatus.TIMEOUT -> "Время проверки вышло: результат неполный, отсутствие замечаний не означает «чисто»."
            QualityStatus.PARTIAL -> "Часть файлов пропущена: отсутствие замечаний в них не означает «чисто»."
            QualityStatus.ISSUES -> "Найдено замечаний: ${sorted.size}."
            else -> "Замечаний нет."
        }
        return report(status, shown, truncated, analyzed, byLanguage, skipped, scan.unsupported, active, started, message)
    }

    private fun report(
        status: QualityStatus, diagnostics: List<QualityDiagnostic>, truncated: Boolean, analyzed: Int,
        byLanguage: Map<String, Int>, skipped: List<SkippedFile>, unsupported: List<String>, active: List<LanguageChecker>,
        started: Long, message: String,
    ) = QualityReport(status, diagnostics, truncated, analyzed, byLanguage, skipped, unsupported, active.flatMap { it.rules },
        (System.nanoTime() - started) / 1_000_000, message)
}

/** Читает рабочую папку только для чтения: без симлинков, с лимитами на число и размер файлов. */
object WorkspaceScanner {
    const val MAX_FILES = 3000
    const val MAX_BYTES = 1_000_000L
    private val SKIP_DIRS = setOf(".git", ".gradle", ".idea", "node_modules", "build", "dist", "out", "target", "venv", ".venv",
        "__pycache__", "site-packages", ".next", "coverage", ".tox", "vendor")

    class Scan(val files: List<SourceUnit>, val skipped: List<SkippedFile>, val unsupported: List<String>, val timedOut: Boolean)

    fun scan(root: Path, extensions: Set<String>, deadline: Deadline): Scan {
        val files = mutableListOf<SourceUnit>()
        val skipped = mutableListOf<SkippedFile>()
        val unsupported = sortedSetOf<String>()
        var timedOut = false
        Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
            override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult =
                if (dir != root && (dir.fileName.toString() in SKIP_DIRS || attrs.isSymbolicLink)) FileVisitResult.SKIP_SUBTREE
                else FileVisitResult.CONTINUE

            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (deadline.expired) { timedOut = true; return FileVisitResult.TERMINATE }
                if (!attrs.isRegularFile || attrs.isSymbolicLink) return FileVisitResult.CONTINUE
                val relative = root.relativize(file).joinToString("/") { it.toString() }
                val ext = relative.substringAfterLast('.', "").lowercase()
                if (ext in UNSUPPORTED_SOURCES) unsupported += ext
                if (ext !in extensions) return FileVisitResult.CONTINUE
                if (relative.endsWith(".min.js")) { skipped += SkippedFile(relative, "Минифицированный файл"); return FileVisitResult.CONTINUE }
                if (files.size >= MAX_FILES) { skipped += SkippedFile(relative, "Превышен лимит $MAX_FILES файлов"); return FileVisitResult.CONTINUE }
                if (attrs.size() > MAX_BYTES) { skipped += SkippedFile(relative, "Файл больше ${MAX_BYTES / 1000} КБ"); return FileVisitResult.CONTINUE }
                val text = readText(file)
                if (text == null) skipped += SkippedFile(relative, "Файл не в кодировке UTF-8")
                else files += SourceUnit(relative, text)
                return FileVisitResult.CONTINUE
            }

            override fun visitFileFailed(file: Path, exc: java.io.IOException) = FileVisitResult.CONTINUE
        })
        files.sortBy { it.path }
        return Scan(files, skipped.sortedBy { it.path }, unsupported.toList(), timedOut)
    }

    private val UNSUPPORTED_SOURCES = setOf("java", "ts", "tsx", "jsx", "go", "rs", "rb", "php", "cs", "cpp", "c", "swift", "scala")

    /** Текст без BOM, переводы строк приведены к `\n`, чтобы номера строк совпадали с редактором. */
    fun readText(path: Path): String? {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return null
        val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            val raw = decoder.decode(java.nio.ByteBuffer.wrap(Files.readAllBytes(path))).toString()
            raw.removePrefix("﻿").replace("\r\n", "\n").replace('\r', '\n')
        } catch (_: CharacterCodingException) { null }
    }
}

/** Смещение → строка и столбец (с единицы). */
class LineIndex(private val text: String) {
    private val starts = IntArray(text.count { it == '\n' } + 1).also { arr ->
        var n = 1
        text.forEachIndexed { i, c -> if (c == '\n') arr[n++] = i + 1 }
    }
    val lineCount: Int get() = starts.size

    fun line(offset: Int): Int {
        val o = offset.coerceIn(0, text.length)
        var lo = 0; var hi = starts.size - 1
        while (lo < hi) { val mid = (lo + hi + 1) ushr 1; if (starts[mid] <= o) lo = mid else hi = mid - 1 }
        return lo + 1
    }

    fun column(offset: Int): Int = offset.coerceIn(0, text.length) - starts[line(offset) - 1] + 1

    /** Смещение последнего непробельного символа: ошибка «в конце файла» относится к последней строке с кодом. */
    fun lastCodeOffset(): Int = text.indexOfLast { !it.isWhitespace() }.coerceAtLeast(0)
}

/** Расстояние Дамерау — Левенштейна (с перестановкой соседних). Для подсказок «возможно, имелось в виду». */
fun editDistance(a: String, b: String): Int {
    if (a == b) return 0
    val d = Array(a.length + 1) { IntArray(b.length + 1) }
    for (i in 0..a.length) d[i][0] = i
    for (j in 0..b.length) d[0][j] = j
    for (i in 1..a.length) for (j in 1..b.length) {
        val cost = if (a[i - 1] == b[j - 1]) 0 else 1
        d[i][j] = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
        if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i][j] = minOf(d[i][j], d[i - 2][j - 2] + 1)
    }
    return d[a.length][b.length]
}

/** Ближайшее известное имя, если опечатка правдоподобна: расстояние 1 для коротких имён, до 2 для длинных. */
fun closeName(name: String, known: Collection<String>, maxDistance: Int = 2): String? {
    if (name.length < 3) return null
    val limit = minOf(maxDistance, if (name.length >= 6) 2 else 1)
    return known.asSequence().filter { it.length >= 3 && it != name && kotlin.math.abs(it.length - name.length) <= limit }
        .map { it to editDistance(name, it) }.filter { it.second in 1..limit }.minByOrNull { it.second }?.first
}
