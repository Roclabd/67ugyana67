package ru.codeguard.sast

import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import ru.codeguard.sast.project.SastProjectLoader
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertTrue

/** Прогон по каждой папке src/test/resources/variants/<имя>/ с expected.json. */
class VariantsTest {

    @TestFactory
    fun variants(): List<DynamicTest> {
        val repoRoot = Paths.get(requireNotNull(System.getProperty("codeguard.repoRoot")) { "не задан codeguard.repoRoot" })
        val dir = repoRoot.resolve("backend/analyzers/sast/src/test/resources/variants")
        val cases: List<Path> = if (Files.isDirectory(dir)) {
            Files.list(dir).use { s ->
                s.filter { Files.isDirectory(it) && Files.isRegularFile(it.resolve("expected.json")) }.sorted().toList()
            }
        } else emptyList()
        if (cases.isEmpty()) return listOf(DynamicTest.dynamicTest("нет вариантов") { })
        return cases.map { c ->
            DynamicTest.dynamicTest(c.fileName.toString()) {
                val (expected, controls) = GroundTruth.readExpected(c.resolve("expected.json"))
                val result = SastAnalyzer().analyze(SastProjectLoader.load(c))
                val m = GroundTruth.match(result.findings, expected, controls)
                val msg = GroundTruth.describe(m, result.findings)
                assertTrue(m.fn.isEmpty(), "Пропущены находки в ${c.fileName}\n$msg")
                assertTrue(m.controlHits.isEmpty(), "Срабатывания на контролях в ${c.fileName}\n$msg")
                assertTrue(m.fp.isEmpty(), "Лишние находки в ${c.fileName}\n$msg")
            }
        }
    }
}
