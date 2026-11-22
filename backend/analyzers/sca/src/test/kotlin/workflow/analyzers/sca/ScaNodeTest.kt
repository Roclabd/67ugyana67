package workflow.analyzers.sca

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import codeguard.analyzers.model.ProjectModelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import workflow.engine.NodeContext
import workflow.engine.NodeInput
import workflow.engine.NodeOutput
import workflow.engine.NodeStatus
import java.nio.file.Files
import java.nio.file.Path

class ScaNodeTest {
    @TempDir
    lateinit var workspace: Path

    @Test
    fun checksBomManagedVersionsAndReportsAnUnavailableReleaseAsUnresolved() {
        val build = "build.gradle.kts"
        val advisoryId = "CG-TEST-SPRING-CORE"
        val independentId = "CG-TEST-INDEPENDENT"
        write("vulnerabilities.json", catalog(
            advisory(advisoryId, "org.springframework", "spring-core",
                range = bounds("7.0.10", "7.0.10", lowerInclusive = true, upperInclusive = true)),
            advisory(independentId, "dev.example", "sentinel"),
        ))
        write("independent/build.gradle.kts", """
            dependencies { implementation("dev.example:sentinel:1.0.0") }
        """)
        fun writeBuild(bootRelease: String) {
            write(build, """
                plugins {
                    id("org.springframework.boot") version "$bootRelease"
                    id("io.spring.dependency-management") version "1.1.7"
                }
                dependencies {
                    implementation("org.springframework:spring-core")
                }
            """)
        }

        writeBuild("4.0.9")
        val managed = scan()
        assertEquals(NodeStatus.SUCCESS, managed.status)
        val finding = managed.findings().single { it.path("advisoryId").asText() == advisoryId }
        assertFinding(finding, "7.0.10", 6, setOf(build to 2, build to 3, build to 6))
        assertBomSource(managed, 2)

        writeBuild("99.0.0")
        val unknown = scan()
        assertEquals(NodeStatus.PARTIAL, unknown.status)
        assertEquals(independentId, unknown.findings().single().path("advisoryId").asText())
        val unresolved = unknown.coverageJson().path("unresolved").single()
        assertEquals("org.springframework:spring-core", unresolved.path("subject").asText())
        assertTrue("99.0.0" in unresolved.path("reason").asText())
    }

    @Test
    fun enforcedBootBomOverridesAnExplicitFixedVersionWithinItsConfigurations() {
        val build = "build.gradle.kts"
        val advisoryId = "CG-TEST-ENFORCED-BOM"
        write("vulnerabilities.json", catalog(
            advisory(advisoryId, "org.springframework", "spring-core",
                range = bounds("7.0.10", "7.0.10", lowerInclusive = true, upperInclusive = true),
                fixedVersion = "7.0.11"),
        ))
        fun writeBuild(scope: String, bootRelease: String) {
            write(build, """
                dependencies {
                    $scope(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:$bootRelease"))
                    implementation("org.springframework:spring-core:7.0.11")
                }
            """)
        }

        writeBuild("implementation", "4.0.9")
        val enforced = scan()
        assertEquals(NodeStatus.SUCCESS, enforced.status)
        val finding = enforced.findings().single { it.path("advisoryId").asText() == advisoryId }
        assertFinding(finding, "7.0.10", 3, setOf(build to 2, build to 3))
        assertEquals("Версия из Spring Boot BOM 4.0.9",
            finding.path("evidence").single { it.path("line").asInt() == 2 }.path("note").asText())
        assertBomSource(enforced, 2)

        writeBuild("implementation", "99.0.0")
        val unknown = scan()
        assertEquals(NodeStatus.PARTIAL, unknown.status)
        assertTrue(unknown.findings().isEmpty())
        assertTrue("99.0.0" in unknown.coverageJson().path("unresolved").single().path("reason").asText())

        writeBuild("testImplementation", "4.0.9")
        val isolated = scan()
        assertEquals(NodeStatus.SUCCESS, isolated.status)
        assertTrue(isolated.findings().isEmpty())
        assertTrue(isolated.coverageJson().path("unresolved").isEmpty)
        assertTrue(isolated.coverageJson().path("springBootBoms").isEmpty)
        assertTrue("7.0.11" in isolated.coverageJson().path("dismissed").single().path("reason").asText())
    }

    private fun assertBomSource(output: NodeOutput, line: Int) {
        val source = output.coverageJson().path("springBootBoms").single()
        assertEquals("4.0.9", source.path("release").asText())
        assertEquals("build.gradle.kts", source.path("path").asText())
        assertEquals(line, source.path("line").asInt())
    }

    @Test
    fun resolvesGradleDeclarationsAndIncludesVersionEvidence() {
        write("build.gradle.kts", """
            val jsonVersion = providers.gradleProperty("jsonVersion").get()

            dependencies {
                implementation("org.json:json:${'$'}jsonVersion")
                implementation(libs.commons.text)
                runtimeOnly("commons-net:commons-net")
            }
        """)
        write("gradle.properties", "jsonVersion=20230618")
        write("gradle/libs.versions.toml", """
            [versions]
            text = "1.9"
            [libraries]
            commons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }
        """)
        write("gradle.lockfile", """
            commons-net:commons-net:3.8.0=runtimeClasspath
            org.jsoup:jsoup:1.14.1=runtimeClasspath
        """)

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        assertEquals("COMPLETE", output.coverageJson().path("status").asText())
        assertEquals(4, output.coverageJson().path("filesAnalyzed").asInt())
        assertTrue(output.coverageJson().path("unresolved").isEmpty)

        val findings = output.findings().associateBy { it.path("artifact").asText() }
        assertEquals(setOf("json", "commons-text", "commons-net"), findings.keys)
        assertFinding(findings.getValue("json"), "20230618", 4, setOf(
            "build.gradle.kts" to 1, "build.gradle.kts" to 4, "gradle.properties" to 1,
        ))
        assertFinding(findings.getValue("commons-text"), "1.9", 5, setOf(
            "build.gradle.kts" to 5, "gradle/libs.versions.toml" to 2, "gradle/libs.versions.toml" to 4,
        ))
        assertFinding(findings.getValue("commons-net"), "3.8.0", 6, setOf(
            "build.gradle.kts" to 6, "gradle.lockfile" to 1,
        ))
    }

    @Test
    fun preservesVulnerableProductionVersionWhenOnlyTestClasspathLocksADifferentVersion() {
        write("build.gradle.kts", """
            dependencies {
                implementation("org.apache.commons:commons-text:1.8")
                testImplementation("org.apache.commons:commons-text")
            }
        """)
        write("gradle.lockfile", "org.apache.commons:commons-text:1.10.0=testRuntimeClasspath")

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        assertEquals("COMPLETE", output.coverageJson().path("status").asText())
        val finding = output.findings().single()
        assertEquals("CVE-2022-42889", finding.path("advisoryId").asText())
        assertFinding(finding, "1.8", 2, setOf("build.gradle.kts" to 2))
        assertEquals(3, output.coverageJson().path("dismissed").single().path("line").asInt())
    }

    @Test
    fun comparesNumericEndpointsWithTrailingZeros() {
        write("build.gradle.kts", """
            dependencies {
                implementation("org.apache.commons:commons-text:1.4.999")
                implementation("org.apache.commons:commons-text:1.5.0")
                implementation("org.apache.commons:commons-text:1.9.0")
                implementation("org.apache.commons:commons-text:1.10")
                implementation("org.json:json:20230618.0")
                implementation("org.json:json:20230619")
            }
        """)

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        assertEquals(
            listOf("1.5.0", "1.9.0", "20230618.0"),
            output.findings().map { it.path("version").asText() },
        )
        assertEquals(
            listOf(2, 5, 7),
            output.coverageJson().path("dismissed").map { it.path("line").asInt() },
        )
    }

    @Test
    fun reportsDistinctAdvisoriesAndRecommendsAnUpgradeOutsideBothRanges() {
        write("build.gradle.kts", """
            dependencies {
                implementation("commons-io:commons-io:2.6")
                testImplementation("commons-io:commons-io:2.6")
            }
        """)

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        val findings = output.findings()
        assertEquals(
            listOf("CVE-2021-29425", "CVE-2024-47554"),
            findings.map { it.path("advisoryId").asText() },
        )
        assertEquals(listOf("MEDIUM", "HIGH"), findings.map { it.path("severity").asText() })
        assertEquals(
            listOf(listOf("2.7"), listOf("2.14.0")),
            findings.map { finding -> finding.path("fixedVersions").map(JsonNode::asText) },
        )
        assertTrue(findings.all { "2.14.0" in it.path("remediation").asText() })
        assertEquals(2, findings.map { it.path("fingerprint").asText() }.toSet().size)
        assertEquals(findings, scan().findings())
    }

    @Test
    fun reportsUnresolvedVersionsForKnownAndUnknownCoordinates() {
        write("build.gradle.kts", """
            dependencies {
                implementation("org.json:json:${'$'}missingVersion")
                implementation("org.apache.commons:commons-text:1.+")
                implementation("org.jsoup:jsoup:1.14.1-preview")
                implementation("com.example:managed-dep")
            }
        """)

        val output = scan()
        assertEquals(NodeStatus.PARTIAL, output.status)
        assertTrue(output.findings().isEmpty())
        val coverage = output.coverageJson()
        assertEquals("PARTIAL", coverage.path("status").asText())
        assertTrue(coverage.path("filesSkipped").isEmpty)
        val unresolved = coverage.path("unresolved")
        assertEquals(
            listOf("org.json:json", "org.apache.commons:commons-text", "org.jsoup:jsoup", "com.example:managed-dep"),
            unresolved.map { it.path("subject").asText() },
        )
        assertEquals(listOf(2, 3, 4, 5), unresolved.map { it.path("line").asInt() })
        assertTrue(unresolved.all {
            it.path("kind").asText() == "dependency-version" &&
                it.path("path").asText() == "build.gradle.kts" &&
                it.path("reason").asText().isNotBlank()
        })
    }

    @Test
    fun keepsCoverageCompleteWhenOnlyAnUnlistedCoordinateIsUnresolved() {
        write("build.gradle.kts", """
            dependencies {
                implementation("com.example:managed-dep")
            }
        """)

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        assertTrue(output.findings().isEmpty())
        val coverage = output.coverageJson()
        assertEquals("COMPLETE", coverage.path("status").asText())
        assertEquals("com.example:managed-dep", coverage.path("unresolved").single().path("subject").asText())
    }

    @Test
    fun findsDeclaredDependenciesInOrganizerSnapshot() {
        val output = scan(Path.of(System.getProperty("training.project")))
        assertEquals(NodeStatus.SUCCESS, output.status)
        val findings = output.findings().associateBy { it.path("artifact").asText() }
        assertEquals(setOf("commons-text", "jsoup", "commons-compress", "commons-net", "json"), findings.keys)
        assertFalse(findings.containsKey("commons-lang3"))
        assertFinding(findings.getValue("json"), "20230227", 38, setOf(
            "build.gradle.kts" to 22, "build.gradle.kts" to 38, "gradle.properties" to 1, "gradle.lockfile" to 25,
        ))
    }

    @Test
    fun reportsSettingsCatalogConstraintAndDefaultPropertyAtDeclaringLines() {
        write("settings.gradle.kts", """
            dependencyResolutionManagement {
                versionCatalogs {
                    create("libs") {
                        library("jsoup", "org.jsoup", "jsoup").version("1.13.1")
                        library("safe-jsoup", "org.jsoup:jsoup:1.18.1")
                    }
                }
            }
        """)
        write("build.gradle.kts", """
            val netVersion = (project.findProperty("netVersion") as String?) ?: "3.8.0"
            dependencies {
                implementation(libs.jsoup)
                implementation(libs.safe.jsoup)
                implementation("commons-net:commons-net:${'$'}netVersion")
                constraints {
                    implementation("org.json:json:20230227")
                    implementation("commons-io:commons-io:2.18.0")
                }
            }
        """)

        val findings = scan().findings().groupBy { it.path("artifact").asText() }
        assertEquals(setOf("jsoup", "commons-net", "json"), findings.keys)
        assertEquals("settings.gradle.kts" to 4, findings.getValue("jsoup").first().let { it.path("path").asText() to it.path("line").asInt() })
        assertEquals("1.13.1", findings.getValue("jsoup").first().path("version").asText())
        assertEquals("build.gradle.kts" to 5, findings.getValue("commons-net").first().let { it.path("path").asText() to it.path("line").asInt() })
        assertEquals("build.gradle.kts" to 7, findings.getValue("json").first().let { it.path("path").asText() to it.path("line").asInt() })
    }

    @Test
    fun loadsNewAdvisoriesFromProjectButCannotNarrowBundledOnes() {
        write("build.gradle.kts", """
            dependencies {
                implementation("example:fixture:1.0")
                implementation("org.apache.commons:commons-text:1.9")
                implementation("org.json:json:20230618")
            }
        """)
        write("data/security/vulnerabilities.json", catalog(
            advisory("CVE-2099-90001", "example", "fixture"),
            advisory("GHSA-599f-7c49-w659", "org.apache.commons", "commons-text", "CVE-2022-42889"),
            snapshotDate = "2026-11-19",
        ))
        write("vulnerability-database/vulnerabilities.json", catalog(
            advisory("CVE-2099-90002", "example", "fixture"),
            snapshotDate = "2026-02-30",
        ))

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        assertEquals(
            setOf("CVE-2099-90001", "CVE-2099-90002", "CVE-2023-5072", "CVE-2022-42889"),
            output.findings().map { it.path("advisoryId").asText() }.toSet(),
        )
        val coverage = output.coverageJson()
        val sources = coverage.path("advisorySources").toList()
        assertEquals(listOf("builtin", "project", "project"), sources.map { it.path("source").asText() })
        assertEquals(listOf("/sca/vulnerabilities.json", "data/security/vulnerabilities.json",
            "vulnerability-database/vulnerabilities.json"), sources.map { it.path("path").asText() })
        assertEquals(listOf(2, 1), sources.drop(1).map { it.path("records").asInt() })
        assertEquals("2026-11-19", sources[1].path("snapshotDate").asText())
        assertFalse(sources[2].has("snapshotDate"))
        assertEquals(sources.first().path("records").asInt() + 2, coverage.path("advisoryCount").asInt())
    }

    @Test
    fun reportsMalformedUnreadableAndUnsupportedCatalogsAndStillUsesBundledDatabase() {
        write("build.gradle.kts", """
            dependencies {
                implementation("org.apache.commons:commons-text:1.9")
            }
        """)
        write("syntax/vulnerabilities.json", catalog() + "{}")
        write("format/vulnerabilities.json", "{}")
        write("encoding/vulnerabilities.json", "")
        Files.write(workspace.resolve("encoding/vulnerabilities.json"), byteArrayOf(0xc0.toByte()))

        val output = scan()
        assertEquals(NodeStatus.PARTIAL, output.status)
        assertEquals("CVE-2022-42889", output.findings().single().path("advisoryId").asText())
        val coverage = output.coverageJson()
        assertEquals("builtin", coverage.path("advisorySources").single().path("source").asText())
        assertEquals("PARTIAL", coverage.path("status").asText())
        val skipped = coverage.path("filesSkipped")
        assertEquals(
            setOf("syntax/vulnerabilities.json", "format/vulnerabilities.json", "encoding/vulnerabilities.json"),
            skipped.map { it.path("path").asText() }.toSet(),
        )
        assertTrue(skipped.all { it.path("reason").asText().isNotBlank() })
    }

    @Test
    fun rejectsInvalidProjectRangesBeforeReplacingBundledAdvisories() {
        write("build.gradle.kts", """
            dependencies {
                implementation("org.apache.commons:commons-text:1.8")
                implementation("example:fixture:1.0")
            }
        """)
        val path = "vulnerability-database/vulnerabilities.json"
        val invalidRanges = listOf(
            bounds("2", "1.1", lowerInclusive = true, upperInclusive = true),
            bounds("1.1", "1.1.0", lowerInclusive = true, upperInclusive = false),
            bounds("1.1.0", "1.1", lowerInclusive = false, upperInclusive = true),
        )
        for (range in invalidRanges) {
            write(path, catalog(
                advisory("CVE-2099-90001", "example", "fixture"),
                advisory("GHSA-599f-7c49-w659", "org.apache.commons", "commons-text", "CVE-2022-42889", range),
            ))

            val output = scan()
            assertEquals(NodeStatus.PARTIAL, output.status, range)
            assertEquals("CVE-2022-42889", output.findings().single().path("advisoryId").asText())
            val coverage = output.coverageJson()
            val source = coverage.path("advisorySources").single()
            assertEquals("builtin", source.path("source").asText())
            assertEquals(source.path("records").asInt(), coverage.path("advisoryCount").asInt())
            val skipped = coverage.path("filesSkipped").single()
            assertEquals(path, skipped.path("path").asText())
            assertEquals("Некорректные границы диапазона версий в справочнике SCA", skipped.path("reason").asText())
        }
    }

    @Test
    fun acceptsAnExactVersionRangeWithBothBoundsInclusive() {
        write("build.gradle.kts", """
            dependencies {
                implementation("example:fixture:0.9")
                implementation("example:fixture:1.0.0")
                implementation("example:fixture:1.1")
            }
        """)
        write("vulnerabilities.json", catalog(
            advisory("CVE-2099-90001", "example", "fixture",
                range = bounds("1.0", "1.0.0", lowerInclusive = true, upperInclusive = true)),
        ))

        val output = scan()
        assertEquals(NodeStatus.SUCCESS, output.status)
        assertEquals("1.0.0", output.findings().single().path("version").asText())
    }

    private fun catalog(vararg advisories: String, snapshotDate: String? = null) = """
        {
            "formatVersion": 1,
            "ecosystem": "Maven",
            "versionFormat": "numeric-dot-separated",
            ${snapshotDate?.let { """"snapshot": {"date": "$it"},""" }.orEmpty()}
            "vulnerabilities": [${advisories.joinToString(",")}]
        }
    """

    private fun advisory(
        id: String,
        group: String,
        artifact: String,
        cve: String? = null,
        range: String = bounds(null, "1.1", lowerInclusive = false, upperInclusive = false),
        fixedVersion: String = "1.1",
    ) = """
        {
            "id": "$id", "group": "$group", "artifact": "$artifact",
            "aliases": [${cve?.let { "\"$it\"" }.orEmpty()}],
            "ranges": [$range],
            "fixedVersions": ["$fixedVersion"], "severity": "HIGH"
        }
    """

    private fun bounds(lower: String?, upper: String, lowerInclusive: Boolean, upperInclusive: Boolean) = """
        {"lower": ${lower?.let { "\"$it\"" }}, "lowerInclusive": $lowerInclusive,
         "upper": "$upper", "upperInclusive": $upperInclusive}
    """

    private fun write(path: String, text: String) {
        val file = workspace.resolve(path)
        Files.createDirectories(file.parent)
        Files.writeString(file, text.trimIndent())
    }

    private fun scan(project: Path = workspace): NodeOutput = ProjectModelBuilder().use { builder ->
        val built = builder.build(project)
        val model = requireNotNull(built.model) { built.summary.toString() }
        val context = object : NodeContext {
            override val runId = "test-run"
            override val nodeId = "sca"
            override val params = JsonNodeFactory.instance.objectNode()
            override val workspace = project
            override val trigger = JsonNodeFactory.instance.objectNode()
            override val coverageStatus = built.summary.status.name
            override fun redact(message: String) = message
            override fun log(message: String) = Unit
            override fun emitProgress(percent: Int, note: String?) = Unit
        }
        runBlocking { ScaNode().run(context, NodeInput(mapOf("model" to model))) }
    }

    private fun NodeOutput.findings(): List<JsonNode> =
        (ports.getValue("findings") as JsonNode).toList()

    private fun NodeOutput.coverageJson(): JsonNode = ObjectMapper().valueToTree(coverage)

    private fun assertFinding(finding: JsonNode, version: String, line: Int, evidence: Set<Pair<String, Int>>) {
        assertEquals("build.gradle.kts", finding.path("path").asText())
        assertEquals(version, finding.path("version").asText())
        assertEquals(line, finding.path("line").asInt())
        assertEquals(evidence, finding.path("evidence").map {
            it.path("path").asText() to it.path("line").asInt()
        }.toSet())
    }
}
