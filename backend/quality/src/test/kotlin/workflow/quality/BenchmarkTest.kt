package workflow.quality

import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Оценка по внешним данным: пары buggy/fixed функциональных дефектов и оракул синтаксиса, типов и ссылок. */
class BenchmarkTest {
    private val engine = QualityEngine(listOf(KotlinChecker(), PythonChecker(), JavaScriptChecker()))
    private val json = ObjectMapper()

    private fun run(name: String, source: String): QualityReport {
        val dir = Files.createTempDirectory("quality-test")
        try {
            Files.writeString(dir.resolve(name), source)
            return engine.run(dir)
        } finally { dir.toFile().deleteRecursively() }
    }

    @Test
    fun functionalPairs() {
        val cases = json.readTree(javaClass.getResource("/benchmark/functional-manifest.json")!!)["cases"]
        var found = 0
        var falseAlarms = 0
        val missed = mutableListOf<String>()
        for (case in cases) {
            val file = "case" + case["extension"].asText()
            val buggy = run(file, case["buggy"].asText()).diagnostics
            val fixed = run(file, case["fixed"].asText()).diagnostics
            if (buggy.any { it.kind == DiagnosticKind.FUNCTIONAL_DEFECT }) found++ else missed += case["id"].asText()
            if (fixed.isNotEmpty()) { falseAlarms++; println("FALSE ALARM ${case["id"].asText()}: $fixed") }
        }
        println("BENCHMARK functional: found=$found/${cases.size()} falseAlarmsOnFixed=$falseAlarms missed=$missed")
        assertEquals(cases.size(), found, "не найдены: $missed")
        assertEquals(0, falseAlarms)
    }

    private data class Oracle(val id: String, val file: String, val source: String, val kind: DiagnosticKind, val line: Int, val column: Int? = null, val fixed: String)

    @Test
    fun diagnosticsOracle() {
        val cases = listOf(
            Oracle("kotlin-incomplete-expression", "Demo.kt", "fun nextValue(value: Int): Int = value +\n", DiagnosticKind.SYNTAX, 1, 41,
                "fun nextValue(value: Int): Int = value + 1\n"),
            Oracle("kotlin-missing-delimiter", "Demo.kt", "fun samples(): List<Int> = listOf(1, 2\n", DiagnosticKind.SYNTAX, 1, 39,
                "fun samples(): List<Int> = listOf(1, 2)\n"),
            Oracle("kotlin-incompatible-return", "Demo.kt", "fun result(): Int = \"hello\"\n", DiagnosticKind.TYPE_MISMATCH, 1, 21,
                "fun result(): Int = 1\n"),
            Oracle("kotlin-unknown-variable", "Demo.kt", "fun result(value: Int): Int = vlaue + 1\n", DiagnosticKind.UNRESOLVED_REFERENCE, 1, 31,
                "fun result(value: Int): Int = value + 1\n"),
            Oracle("python-missing-colon", "Demo.py", "def total(values)\n    return sum(values)\n", DiagnosticKind.SYNTAX, 1, null,
                "def total(values):\n    return sum(values)\n"),
            Oracle("javascript-missing-brace", "Demo.js", "function total(values) {\n  return values.length;\n", DiagnosticKind.SYNTAX, 2, null,
                "function total(values) {\n  return values.length;\n}\n"),
        )
        var passed = 0
        for (c in cases) {
            val d = run(c.file, c.source).diagnostics.firstOrNull { it.kind == c.kind && it.line == c.line && (c.column == null || it.column == c.column) }
            val clean = run(c.file, c.fixed).diagnostics
            if (d != null && clean.isEmpty()) passed++ else println("ORACLE MISS ${c.id}: got=${run(c.file, c.source).diagnostics} fixed=$clean")
        }
        println("BENCHMARK oracle: $passed/${cases.size}")
        assertEquals(cases.size, passed)
    }

    @Test
    fun pythonAndJavaScriptReferencesAndTypes() {
        val py = run("a.py", "import os\n\ndef f(items):\n    total = 0\n    for item in items:\n        total += item\n    return totl\n\nx: int = \"a\"\n")
        assertTrue(py.diagnostics.any { it.kind == DiagnosticKind.UNRESOLVED_REFERENCE && it.line == 7 })
        assertTrue(py.diagnostics.any { it.kind == DiagnosticKind.TYPE_MISMATCH && it.line == 9 })
        val js = run("a.js", "function f(value) {\n  return vlaue + 1;\n}\nif ([1] == []) {}\n")
        assertTrue(js.diagnostics.any { it.kind == DiagnosticKind.UNRESOLVED_REFERENCE && it.line == 2 })
        assertTrue(js.diagnostics.any { it.rule == "javascript.defect.array-equality" && it.line == 4 })
    }

    @Test
    fun cleanCodeStaysSilentAndStatusesAreHonest() {
        val clean = run("ok.py", "import os\n\n\ndef f(items, flag=None):\n    out = []\n    for item in items:\n        out.append(os.path.join('a', item))\n    return out\n")
        assertEquals(QualityStatus.OK, clean.status)
        assertEquals(QualityStatus.NOT_APPLICABLE, run("readme.txt", "hello").status)
        val broken = Files.createTempDirectory("quality-bin")
        try {
            Files.write(broken.resolve("bad.py"), byteArrayOf(0xC3.toByte(), 0x28))
            assertEquals(QualityStatus.PARTIAL, engine.run(broken).status)
            Files.writeString(broken.resolve("x.kt"), "fun a() = 1\n")
            val timed = engine.run(broken, QualityOptions(timeoutMillis = -1000))
            assertEquals(QualityStatus.TIMEOUT, timed.status)
        } finally { broken.toFile().deleteRecursively() }
    }

    /** Ручной прогон по чужому коду для оценки ложных срабатываний: QUALITY_SAMPLE=<папка>. */
    @Test
    fun sampleDirectory() {
        val dir = System.getenv("QUALITY_SAMPLE") ?: return
        val report = engine.run(Path.of(dir), QualityOptions(maxDiagnostics = 5000, timeoutMillis = 120_000))
        println("SAMPLE status=${report.status} files=${report.filesByLanguage} total=${report.diagnostics.size} skipped=${report.skipped.size}")
        report.diagnostics.forEach { println("SAMPLE ${it.language} ${it.rule} ${it.path}:${it.line}:${it.column} ${it.confidence} ${it.message.take(110)}") }
    }
}
