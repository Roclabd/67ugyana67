package ru.codeguard.sast.project

import org.jetbrains.kotlin.cli.common.CLIConfigurationKeys
import org.jetbrains.kotlin.cli.common.messages.MessageCollector
import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.com.intellij.openapi.Disposable
import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer
import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.PsiErrorElement
import org.jetbrains.kotlin.com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.config.CommonConfigurationKeys
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtPsiFactory
import ru.codeguard.sast.model.Location
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.isRegularFile
import kotlin.io.path.relativeTo

/**
 * Исходный файл с текстом, нормализованным для PSI, и картой строк.
 * Номера строк совпадают с исходным файлом: CRLF и одиночный CR считаются одним переносом,
 * начальный BOM удаляется (contracts/project-model.md, «Правила модели»).
 */
class SourceText(val path: String, raw: String) {
    val text: String = normalize(raw)
    private val lineStarts: IntArray = buildLineStarts(text)

    /** Номер строки (с 1) для смещения в [text]. */
    fun lineOf(offset: Int): Int {
        var lo = 0
        var hi = lineStarts.size - 1
        while (lo < hi) {
            val mid = (lo + hi + 1) ushr 1
            if (lineStarts[mid] <= offset) lo = mid else hi = mid - 1
        }
        return lo + 1
    }

    companion object {
        fun normalize(raw: String): String = raw.removePrefix("﻿").replace("\r\n", "\n").replace('\r', '\n')

        private fun buildLineStarts(text: String): IntArray {
            val starts = ArrayList<Int>()
            starts += 0
            text.forEachIndexed { i, c -> if (c == '\n') starts += i + 1 }
            return starts.toIntArray()
        }
    }
}

class KotlinSource(val source: SourceText, val psi: KtFile) {
    val path: String get() = source.path

    fun line(e: PsiElement): Int = source.lineOf(e.textRange.startOffset)
    fun endLine(e: PsiElement): Int = source.lineOf(maxOf(e.textRange.startOffset, e.textRange.endOffset - 1))
    fun loc(e: PsiElement, note: String? = null): Location {
        val l = line(e)
        val el = endLine(e)
        return Location(path, l, if (el > l) el else null, note)
    }
}

data class ParseError(val path: String, val line: Int?, val message: String)

/**
 * Вход SAST: разобранные Kotlin-файлы и тексты остальных файлов (SQL, YAML, …).
 * Пока нет ProjectModel (задача C3), строится [SastProjectLoader]; затем — адаптером из ProjectModel.
 */
class SastProject(
    val kotlin: List<KotlinSource>,
    val textFiles: Map<String, SourceText>,
    val parseErrors: List<ParseError>,
)

/** Разбор каталога проекта в [SastProject]. Окружение Kotlin PSI создаётся один раз на процесс. */
object SastProjectLoader {
    private val disposable: Disposable = Disposer.newDisposable("codeguard-sast")
    private val factory: KtPsiFactory by lazy {
        val config = CompilerConfiguration().apply {
            put(CommonConfigurationKeys.MODULE_NAME, "codeguard-sast")
            put(CLIConfigurationKeys.MESSAGE_COLLECTOR_KEY, MessageCollector.NONE)
        }
        val env = KotlinCoreEnvironment.createForProduction(disposable, config, EnvironmentConfigFiles.JVM_CONFIG_FILES)
        KtPsiFactory(env.project, markGenerated = false)
    }

    private val SKIP_DIRS = setOf(".git", ".gradle", "build", "out", "node_modules", ".idea")
    private val TEXT_EXT = setOf("sql", "yml", "yaml", "properties", "xml", "kts")

    fun parseKotlin(path: String, raw: String): Pair<KotlinSource, List<ParseError>> {
        val source = SourceText(path, raw)
        val psi = synchronized(this) { factory.createFile(path.substringAfterLast('/'), source.text) }
        val errors = PsiTreeUtil.collectElementsOfType(psi, PsiErrorElement::class.java).map {
            ParseError(path, source.lineOf(it.textRange.startOffset), it.errorDescription)
        }
        return KotlinSource(source, psi) to errors
    }

    fun load(root: Path): SastProject {
        val kotlin = mutableListOf<KotlinSource>()
        val texts = mutableMapOf<String, SourceText>()
        val errors = mutableListOf<ParseError>()
        Files.walk(root).use { stream ->
            stream.filter { it.isRegularFile() }
                .filter { p -> root.relativize(p).none { it.toString() in SKIP_DIRS } }
                .sorted()
                .forEach { p ->
                    val rel = p.relativeTo(root).joinToString("/")
                    val ext = p.extension.lowercase()
                    if (ext == "kt") {
                        val raw = try {
                            Files.readString(p)
                        } catch (e: Exception) {
                            errors += ParseError(rel, null, "Не удалось прочитать файл: ${e.message}")
                            return@forEach
                        }
                        val (src, errs) = parseKotlin(rel, raw)
                        kotlin += src
                        errors += errs
                    } else if (ext in TEXT_EXT) {
                        runCatching { Files.readString(p) }.onSuccess { texts[rel] = SourceText(rel, it) }
                    }
                }
        }
        return SastProject(kotlin, texts, errors)
    }
}
