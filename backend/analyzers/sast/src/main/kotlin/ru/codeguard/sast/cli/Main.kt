package ru.codeguard.sast.cli

import ru.codeguard.sast.SastAnalyzer
import ru.codeguard.sast.export.OrganizerJson
import ru.codeguard.sast.project.SastProjectLoader
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess

/** Запуск: <каталог проекта> [файл для JSON]. Без файла JSON печатается в stdout, сводка — всегда в stderr. */
fun main(args: Array<String>) {
    val err = PrintStream(System.err, true, Charsets.UTF_8)
    if (args.isEmpty() || args.size > 2) {
        err.println("Использование: sast <каталог проекта> [файл для JSON]")
        exitProcess(2)
    }
    val root: Path = Paths.get(args[0])
    if (!Files.isDirectory(root)) {
        err.println("Каталог проекта не найден: ${args[0]}")
        exitProcess(2)
    }
    val result = SastAnalyzer().analyze(SastProjectLoader.load(root))
    val json = OrganizerJson.toJson(result)
    if (args.size == 2) {
        val out = Paths.get(args[1]).toAbsolutePath()
        out.parent?.let { Files.createDirectories(it) }
        Files.writeString(out, json, Charsets.UTF_8)
    } else {
        PrintStream(System.out, true, Charsets.UTF_8).print(json)
    }
    val c = result.coverage
    err.println("Покрытие: ${c.status}, файлов проанализировано ${c.filesAnalyzed}, пропущено ${c.filesSkipped.size}")
    err.println("Находок: ${result.findings.size}")
    result.findings.groupingBy { it.sastClass }.eachCount().toSortedMap().forEach { (k, v) -> err.println("  $k: $v") }
    err.println("unresolved: ${c.unresolved.size}, dismissed: ${c.dismissed.size}")
    c.unresolved.forEach { err.println("  ? ${it.path}:${it.line ?: "-"} ${it.reason}") }
    c.dismissed.forEach { err.println("  ✓ ${it.path}:${it.line ?: "-"} [${it.rule}] ${it.reason}") }
}
