package workflow.app

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class FindingPatchesTest {
    private val json = ObjectMapper()

    private fun sca(path: String, line: Int, version: String, remediation: String, evidence: List<Pair<String, Int>>) =
        json.readTree(json.writeValueAsString(mapOf(
            "id" to "sca-1", "category" to "SCA", "path" to path, "line" to line, "version" to version,
            "group" to "com.fasterxml.jackson.core", "artifact" to "jackson-databind", "remediation" to remediation,
            "evidence" to evidence.map { mapOf("path" to it.first, "line" to it.second) },
        )))

    private fun secret(path: String, line: Int) = json.readTree(json.writeValueAsString(mapOf(
        "id" to "secret-1", "category" to "SECRET", "path" to path, "line" to line, "class" to "password",
    )))

    private fun files(vararg entries: Pair<String, String>): (String) -> String? = entries.toMap()::get

    private fun ready(outcome: PatchOutcome) = (outcome as PatchOutcome.Ready)

    @Test fun `sca literal in build gradle kts is bumped to the first safe version`() {
        val build = "plugins {\n    kotlin(\"jvm\")\n}\n\ndependencies {\n    implementation(\"com.fasterxml.jackson.core:jackson-databind:2.9.0\")\n    testImplementation(\"junit:junit:4.13\")\n}\n"
        val finding = sca("build.gradle.kts", 6, "2.9.0",
            "Обновите com.fasterxml.jackson.core:jackson-databind до версии 2.9.10.4.", listOf("build.gradle.kts" to 6))
        val diff = ready(FindingPatches.create(finding, files("build.gradle.kts" to build))).diff
        assertTrue(diff.startsWith("--- a/build.gradle.kts\n+++ b/build.gradle.kts\n@@ -3,6 +3,6 @@\n"), diff)
        assertTrue(diff.contains("-    implementation(\"com.fasterxml.jackson.core:jackson-databind:2.9.0\")\n"))
        assertTrue(diff.contains("+    implementation(\"com.fasterxml.jackson.core:jackson-databind:2.9.10.4\")\n"))
        assertTrue(diff.contains(" }\n"))
    }

    @Test fun `sca version from gradle properties is patched where it is declared`() {
        val build = "dependencies {\n    implementation(\"com.fasterxml.jackson.core:jackson-databind:\$jacksonVersion\")\n}\n"
        val properties = "org.gradle.jvmargs=-Xmx1g\njacksonVersion=2.9.0\n"
        val finding = sca("build.gradle.kts", 2, "2.9.0",
            "Обновите com.fasterxml.jackson.core:jackson-databind до версии 2.9.10.4.",
            listOf("build.gradle.kts" to 2, "gradle.properties" to 2))
        val diff = ready(FindingPatches.create(finding, files("build.gradle.kts" to build, "gradle.properties" to properties))).diff
        assertTrue(diff.startsWith("--- a/gradle.properties\n+++ b/gradle.properties\n@@ -1,2 +1,2 @@\n"), diff)
        assertTrue(diff.contains("-jacksonVersion=2.9.0\n+jacksonVersion=2.9.10.4\n"))
    }

    @Test fun `sca ignores the generated lockfile as a place to patch`() {
        val finding = sca("build.gradle.kts", 1, "1.9", "Обновите g:a до версии 1.10.",
            listOf("build.gradle.kts" to 1, "gradle.lockfile" to 1))
        val diff = ready(FindingPatches.create(finding,
            files("build.gradle.kts" to "implementation(\"g:a:1.9\")\n", "gradle.lockfile" to "g:a:1.9=compileClasspath\n"))).diff
        assertTrue(diff.startsWith("--- a/build.gradle.kts\n"), diff)
        assertTrue(diff.contains("+implementation(\"g:a:1.10\")\n"))
    }

    @Test fun `sca without literal version or safe target is unsupported`() {
        val build = "implementation(\"g:a:\${computed()}\")\n"
        val computed = sca("build.gradle.kts", 1, "2.9.0", "Обновите g:a до версии 2.9.10.4.", listOf("build.gradle.kts" to 1))
        assertTrue(FindingPatches.create(computed, files("build.gradle.kts" to build)) is PatchOutcome.Unsupported)
        val noTarget = sca("build.gradle.kts", 1, "2.9.0", "Проверьте доступные обновления.", listOf("build.gradle.kts" to 1))
        assertTrue(FindingPatches.create(noTarget, files("build.gradle.kts" to "x:2.9.0")) is PatchOutcome.Unsupported)
        val similar = sca("build.gradle.kts", 1, "2.9.0", "Обновите g:a до версии 3.0.", listOf("build.gradle.kts" to 1))
        assertTrue(FindingPatches.create(similar, files("build.gradle.kts" to "implementation(\"g:a:12.9.0\")\n")) is PatchOutcome.Unsupported)
    }

    @Test fun `kotlin secret val is replaced by environment lookup and masked in preview`() {
        val source = "package demo\n\nobject Config {\n    val apiKey = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n}\n"
        val outcome = ready(FindingPatches.create(secret("Config.kt", 4), files("Config.kt" to source)))
        assertTrue(outcome.diff.contains("-    val apiKey = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n"))
        assertTrue(outcome.diff.contains("+    val apiKey = System.getenv(\"API_KEY\") ?: error(\"API_KEY is not set\")\n"))
        assertFalse(outcome.preview.contains("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
        assertTrue(outcome.preview.contains("-    val apiKey = \"****\"\n"))
    }

    @Test fun `const val loses const and chained call keeps precedence`() {
        val constant = ready(FindingPatches.create(secret("A.kt", 1), files("A.kt" to "const val dbPassword = \"Zx9!kQ2mLp0w\"\n")))
        assertTrue(constant.diff.contains("+val dbPassword = System.getenv(\"DB_PASSWORD\") ?: error(\"DB_PASSWORD is not set\")\n"))
        val chained = ready(FindingPatches.create(secret("A.kt", 1), files("A.kt" to "val key = \"Zx9kQ2mLp0w\".toByteArray()\n")))
        assertTrue(chained.diff.contains("+val key = (System.getenv(\"KEY\") ?: error(\"KEY is not set\")).toByteArray()\n"))
    }

    @Test fun `yaml secret becomes a placeholder named after the key path`() {
        val yaml = "spring:\n  datasource:\n    url: jdbc:h2:mem:test\n    password: Zx9kQ2mLp0w\n"
        val outcome = ready(FindingPatches.create(secret("src/main/resources/application.yml", 4),
            files("src/main/resources/application.yml" to yaml)))
        assertTrue(outcome.diff.contains("-    password: Zx9kQ2mLp0w\n+    password: \${SPRING_DATASOURCE_PASSWORD}\n"), outcome.diff)
        assertTrue(outcome.preview.contains("-    password: ****\n"))
        val properties = ready(FindingPatches.create(secret("app.properties", 1),
            files("app.properties" to "db.password=Zx9kQ2mLp0w\n")))
        assertTrue(properties.diff.contains("+db.password=\${DB_PASSWORD}\n"))
    }

    @Test fun `secret in an unknown file type or ambiguous line is unsupported and sast has no autofix`() {
        assertTrue(FindingPatches.create(secret("run.sh", 1), files("run.sh" to "TOKEN=abc123\n")) is PatchOutcome.Unsupported)
        assertTrue(FindingPatches.create(secret("A.kt", 1), files("A.kt" to "val a = \"x1\"; val b = \"y2\"\n")) is PatchOutcome.Unsupported)
        val sast = json.readTree("""{"category":"SAST","path":"A.kt","line":1}""")
        assertTrue(FindingPatches.create(sast, files()) is PatchOutcome.NoAutofix)
    }

    @Test fun `diff keeps crlf and marks a missing final newline`() {
        val diff = FindingPatches.lineDiff("a.txt", "one\r\ntwo\r\nthree", 3, "four")
        assertEquals("--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\r\n two\r\n-three\n\\ No newline at end of file\n+four\n\\ No newline at end of file\n", diff)
    }
}
