package ru.codeguard.sast

import ru.codeguard.sast.export.OrganizerJson
import ru.codeguard.sast.model.CoverageStatus
import ru.codeguard.sast.model.SastResult
import ru.codeguard.sast.project.SastProjectLoader
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Прогон на учебном проекте авторов набора против эталона (только SAST). */
class TrainingProjectTest {

    private val repoRoot: Path = Paths.get(requireNotNull(System.getProperty("codeguard.repoRoot")) { "не задан codeguard.repoRoot" })
    private val projectDir: Path = repoRoot.resolve("fixtures/training/sample-project")
    private val gt = GroundTruth.readOrganizerSast(repoRoot.resolve("fixtures/training/ground-truth/training-findings.json"))
    private val expected = gt.first
    private val controls = gt.second

    private fun run(): SastResult = SastAnalyzer().analyze(SastProjectLoader.load(projectDir))
    private val result: SastResult by lazy { run() }
    private val match by lazy { GroundTruth.match(result.findings, expected, controls) }
    private fun report() = GroundTruth.describe(match, result.findings)

    @Test
    fun `эталон содержит пять SAST-находок`() {
        assertEquals(5, expected.size, "SAST-находок в эталоне: $expected")
    }

    @Test
    fun `все SAST-находки эталона найдены`() {
        assertTrue(match.fn.isEmpty(), "Пропущены: ${match.fn}\n${report()}")
    }

    @Test
    fun `нет срабатываний на контролях`() {
        assertTrue(match.controlHits.isEmpty(), "Срабатывания на контролях\n${report()}")
    }

    @Test
    fun `нет лишних находок`() {
        assertTrue(match.fp.isEmpty(), "Лишние находки\n${report()}")
    }

    @Test
    fun `покрытие полное`() {
        val c = result.coverage
        assertEquals(CoverageStatus.COMPLETE, c.status, "skipped=${c.filesSkipped}, unresolved=${c.unresolved}")
    }

    @Test
    fun `результат детерминирован`() {
        assertEquals(OrganizerJson.toJson(run()), OrganizerJson.toJson(run()))
    }

    @Test
    fun `у находок есть доказательство и диапазон не больше 15 строк`() {
        for (f in result.findings) {
            assertTrue(f.evidence.isNotEmpty(), "Пустой evidence: ${f.sastClass} ${f.path}:${f.line}")
            val end = f.endLine
            assertTrue(end == null || (end >= f.line && end <= f.line + 14), "Плохой диапазон: ${f.path}:${f.line}-$end")
        }
    }

    @Test
    fun `значения секретов не попадают в JSON`() {
        val json = OrganizerJson.toJson(result) + OrganizerJson.coverageJson(result)
        assertFalse(json.contains("codeguard_"), "В JSON найдена подстрока codeguard_")
    }
}
