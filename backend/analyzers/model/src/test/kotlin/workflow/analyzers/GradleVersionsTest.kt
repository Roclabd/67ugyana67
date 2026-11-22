package workflow.analyzers

import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ModelStatus
import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class GradleVersionsTest {
    @TempDir
    lateinit var workspace: Path

    @Test
    fun resolvesStaticVersionSourcesAndKeepsTheirLocations() {
        val build = "build.gradle.kts"
        val properties = "gradle.properties"
        val catalog = "gradle/libs.versions.toml"
        Files.writeString(workspace.resolve(build), """
            extra["extraRelease"] = "1.2.3"
            val literalRelease = "2.3.4"
            val propertyRelease: String by project

            dependencies {
                val localRelease = "3.4.5"
                implementation("demo:extra:${'$'}{extra["extraRelease"]}")
                implementation("demo:literal:${'$'}literalRelease")
                implementation(group = "demo", name = "local", version = localRelease)
                implementation(libs.bundles.catalog.items)
                implementation("demo:property:${'$'}propertyRelease")
            }
        """.trimIndent())
        Files.writeString(workspace.resolve(properties), "propertyRelease=5.6.7\n")
        Files.createDirectories(workspace.resolve("gradle"))
        Files.writeString(workspace.resolve(catalog), """
            [versions]
            catalog-release = { strictly = "4.5.6" }

            [libraries]
            catalog-item = { module = "demo:catalog", version.ref = "catalog-release" }

            [bundles]
            catalog-items = ["catalog-item"]
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val result = builder.build(workspace)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            val dependencies = model.gradle.dependencies.associateBy { it.artifact }
            assertEquals(
                mapOf("extra" to "1.2.3", "literal" to "2.3.4", "local" to "3.4.5",
                    "catalog" to "4.5.6", "property" to "5.6.7"),
                dependencies.mapValues { it.value.resolvedVersion },
            )
            assertEquals(
                mapOf(
                    "extra" to listOf(Location(build, 7), Location(build, 1)),
                    "literal" to listOf(Location(build, 8), Location(build, 2)),
                    "local" to listOf(Location(build, 9), Location(build, 6)),
                    "catalog" to listOf(Location(build, 10), Location(catalog, 8), Location(catalog, 5), Location(catalog, 2)),
                    "property" to listOf(Location(build, 11), Location(build, 3), Location(properties, 1)),
                ),
                dependencies.mapValues { it.value.resolution },
            )
        }
    }

    @Test
    fun keepsMainAndTestLockVersionsSeparate() {
        val build = "build.gradle.kts"
        val lockfile = "gradle.lockfile"
        Files.writeString(workspace.resolve(build), """
            dependencies {
                implementation("demo:split:1.0")
                testImplementation("demo:split")
                implementation("demo:test-lock-only:1.0")
                testImplementation("demo:main-lock-only")
            }
        """.trimIndent())
        Files.writeString(workspace.resolve(lockfile), """
            demo:split:2.0=compileClasspath, runtimeClasspath
            demo:split:3.0=testCompileClasspath,testRuntimeClasspath
            demo:test-lock-only:3.0=testRuntimeClasspath
            demo:main-lock-only:2.0=runtimeClasspath
            empty=annotationProcessor
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val result = builder.build(workspace)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            val dependencies = model.gradle.dependencies
            assertEquals(listOf("2.0", "3.0", "1.0", null), dependencies.map { it.resolvedVersion })
            assertEquals(listOf("1.0", null, "1.0", null), dependencies.map { it.declaredVersion })
            assertEquals(
                listOf(
                    listOf(Location(build, 2), Location(lockfile, 1)),
                    listOf(Location(build, 3), Location(lockfile, 2)),
                    listOf(Location(build, 4)),
                    listOf(Location(build, 5)),
                ),
                dependencies.map { it.resolution },
            )
        }
    }

    @Test
    fun usesTheActiveBootBomAfterApplicableLocksAndExplicitVersions() {
        val build = "build.gradle.kts"
        val lock = "gradle.lockfile"
        Files.writeString(workspace.resolve(build), """
            plugins {
                id("org.springframework.boot") version "4.0.9"
                id("io.spring.dependency-management") version "1.1.7"
            }
            dependencies {
                implementation("org.springframework:spring-core")
                implementation("org.springframework:spring-beans:7.0.1")
                implementation("org.springframework:spring-web")
            }
        """.trimIndent())
        Files.writeString(workspace.resolve(lock), "org.springframework:spring-web:7.0.9=runtimeClasspath\n")

        ProjectModelBuilder().use { builder ->
            val result = builder.build(workspace)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            val (managed, explicit, locked) = model.gradle.dependencies
            assertEquals("7.0.10", managed.resolvedVersion)
            assertNull(managed.declaredVersion)
            assertTrue(Location(build, 2) in managed.resolution)
            assertTrue(Location(build, 3) in managed.resolution)
            assertEquals("7.0.1", explicit.resolvedVersion)
            assertEquals(listOf(Location(build, 7)), explicit.resolution)
            assertEquals("7.0.9", locked.resolvedVersion)
            assertEquals(listOf(Location(build, 8), Location(lock, 1)), locked.resolution)
        }
    }

    @Test
    fun appliesAnExplicitBootPlatformOnlyToItsSupportedConfigurations() {
        val build = "build.gradle.kts"
        Files.writeString(workspace.resolve("gradle.properties"), "bootRelease=3.5.8\n")
        Files.writeString(workspace.resolve(build), """
            val bootRelease: String by project
            dependencies {
                testImplementation(platform("org.springframework.boot:spring-boot-dependencies:${'$'}bootRelease"))
                implementation("org.springframework:spring-core")
                testImplementation("org.springframework:spring-core")
            }
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val result = builder.build(workspace)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            val dependencies = model.gradle.dependencies.filter { it.artifact == "spring-core" }
                .associateBy { it.configuration }
            assertNull(dependencies.getValue("implementation").resolvedVersion)
            val managed = dependencies.getValue("testImplementation")
            assertEquals("6.2.14", managed.resolvedVersion)
            assertTrue(Location(build, 3) in managed.resolution)
            assertTrue(Location("gradle.properties", 1) in managed.resolution)

            Files.writeString(workspace.resolve("gradle.lockfile"),
                "org.springframework.boot:spring-boot-dependencies:4.0.9=testCompileClasspath,testRuntimeClasspath\n")
            val lockedModel = requireNotNull(builder.build(workspace).model)
            val locked = lockedModel.gradle.dependencies.single {
                it.artifact == "spring-core" && it.configuration == "testImplementation"
            }
            assertEquals("7.0.10", locked.resolvedVersion)
            assertTrue(Location("gradle.lockfile", 1) in locked.resolution)

            Files.writeString(workspace.resolve("gradle.lockfile"),
                "org.springframework.boot:spring-boot-dependencies:4.0.9=testRuntimeClasspath\n")
            val partialModel = requireNotNull(builder.build(workspace).model)
            val partialLock = partialModel.gradle.dependencies.single {
                it.artifact == "spring-core" && it.configuration == "testImplementation"
            }
            assertNull(partialLock.resolvedVersion)
            assertTrue("части применимых classpath" in partialLock.unresolvedReason.orEmpty())
        }
    }

    @Test
    fun doesNotInferFromAnUnappliedBootPlugin() {
        val build = "build.gradle.kts"
        Files.writeString(workspace.resolve(build), """
            plugins {
                id("org.springframework.boot") version "4.0.9" apply false
                id("io.spring.dependency-management") version "1.1.7"
            }
            dependencies {
                implementation("org.springframework:spring-core")
            }
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            assertNull(model.gradle.dependencies.single().resolvedVersion)
        }
    }

    @Test
    fun flagsAnOverrideInsteadOfInferringTheDefaultBootVersion() {
        val build = "build.gradle.kts"
        Files.writeString(workspace.resolve(build), """
            plugins {
                id("org.springframework.boot") version "4.0.9"
                id("io.spring.dependency-management") version "1.1.7"
            }
            extra["spring-framework.version"] = "7.0.9"
            dependencies {
                implementation("org.springframework:spring-core")
            }
        """.trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val dependency = model.gradle.dependencies.single()
            assertNull(dependency.resolvedVersion)
            assertTrue("переопределена" in dependency.unresolvedReason.orEmpty())
            assertTrue(Location(build, 5) in dependency.resolution)
        }
    }

    @Test
    fun keepsAChildVersionUnresolvedWhenTheRootConfiguresSubprojects() {
        Files.writeString(workspace.resolve("build.gradle.kts"), """
            dependencies { implementation("org.springframework:spring-core:7.0.11") }
            subprojects {
                dependencies {
                    add("implementation", enforcedPlatform("org.springframework.boot:spring-boot-dependencies:4.0.9"))
                }
            }
        """.trimIndent())
        Files.createDirectories(workspace.resolve("member"))
        Files.writeString(workspace.resolve("member/build.gradle.kts"),
            """dependencies { implementation("org.springframework:spring-core:7.0.11") }""")

        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val targets = model.gradle.dependencies.filter { it.artifact == "spring-core" }
                .associateBy { it.declaredAt.path }
            assertEquals("7.0.11", targets.getValue("build.gradle.kts").resolvedVersion)
            val child = targets.getValue("member/build.gradle.kts")
            assertNull(child.resolvedVersion)
            assertTrue(child.unresolvedReason.orEmpty().contains("BOM"))
            assertTrue(Location("build.gradle.kts", 4) in child.resolution)
        }
    }

    @Test
    fun keepsAnExplicitVersionUnresolvedWhenEnforcedPlatformScopeIsUnknown() {
        Files.writeString(workspace.resolve("build.gradle.kts"), """
            dependencies {
                implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:4.0.9"))
                add("featureImplementation", "org.springframework:spring-core:7.0.11")
            }
        """.trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val target = model.gradle.dependencies.single { it.artifact == "spring-core" }
            assertNull(target.resolvedVersion)
            assertTrue(target.unresolvedReason.orEmpty().contains("BOM"))
            assertTrue(Location("build.gradle.kts", 2) in target.resolution)
        }
    }

    @Test
    fun keepsAnExplicitVersionUnresolvedWhenTheEnforcedPlatformIsConditional() {
        val build = "build.gradle.kts"
        Files.writeString(workspace.resolve(build), """
            dependencies {
                if (providers.gradleProperty("useBom").isPresent) {
                    implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:4.0.9"))
                }
                implementation("org.springframework:spring-core:7.0.11")
            }
        """.trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val target = model.gradle.dependencies.single { it.artifact == "spring-core" }
            assertNull(target.resolvedVersion)
            assertTrue(target.unresolvedReason.orEmpty().contains("BOM"))
            assertTrue(Location(build, 3) in target.resolution)
        }
    }

    @Test
    fun keepsAnExplicitVersionUnresolvedWhenTheNativePlatformVersionIsUncertain() {
        Files.writeString(workspace.resolve("build.gradle.kts"), """
            dependencies {
                implementation(platform("org.springframework.boot:spring-boot-dependencies:99.0.0"))
                implementation("org.springframework:spring-core:7.0.11")
            }
        """.trimIndent())
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(workspace).model)
            val target = model.gradle.dependencies.single { it.artifact == "spring-core" }
            assertNull(target.resolvedVersion)
            assertTrue(target.unresolvedReason.orEmpty().contains("99.0.0"))

            val buildFile = workspace.resolve("build.gradle.kts")
            Files.writeString(buildFile, Files.readString(buildFile).replace("99.0.0", "4.0.9"))
            val conflicting = requireNotNull(builder.build(workspace).model).gradle.dependencies
                .single { it.artifact == "spring-core" }
            assertNull(conflicting.resolvedVersion)
            assertTrue(conflicting.unresolvedReason.orEmpty().contains("отличается"))
        }
    }

    @Test
    fun matchesJvmCompileAndRuntimeScopes() {
        Files.writeString(workspace.resolve("build.gradle.kts"), """
            dependencies {
                api("demo:api")
                compileOnly("demo:compile-only")
                compileOnlyApi("demo:compile-only-api")
                add("runtimeOnly", "demo:runtime-only")
                testCompileOnly("demo:test-compile-only")
                testRuntimeOnly("demo:test-runtime-only")
                annotationProcessor("demo:processor")
            }
        """.trimIndent())
        Files.writeString(workspace.resolve("gradle.lockfile"), """
            demo:api:2.0=runtimeClasspath
            demo:compile-only:2.0=compileClasspath
            demo:compile-only:3.0=runtimeClasspath
            demo:compile-only-api:2.0=compileClasspath
            demo:compile-only-api:3.0=runtimeClasspath
            demo:runtime-only:2.0=runtimeClasspath
            demo:runtime-only:3.0=compileClasspath
            demo:test-compile-only:2.0=testCompileClasspath
            demo:test-compile-only:3.0=testRuntimeClasspath
            demo:test-runtime-only:2.0=testRuntimeClasspath
            demo:test-runtime-only:3.0=testCompileClasspath
            demo:processor:2.0=annotationProcessor
            demo:processor:3.0=testAnnotationProcessor
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val result = builder.build(workspace)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            assertEquals(List(7) { "2.0" }, model.gradle.dependencies.map { it.resolvedVersion })
        }
    }

    @Test
    fun leavesConflictingVersionsAndUncertainLockScopesUnresolved() {
        val lockfile = "gradle.lockfile"
        Files.writeString(workspace.resolve("build.gradle.kts"), """
            dependencies {
                implementation("demo:conflict:1.0")
                implementation("demo:unmapped-lock:1.0")
                add("customDependencies", "demo:unmapped-declaration:1.0")
                add("customResolvable", "demo:custom:1.0")
            }
        """.trimIndent())
        Files.writeString(workspace.resolve(lockfile), """
            demo:conflict:2.0=compileClasspath
            demo:conflict:3.0=runtimeClasspath
            demo:conflict:4.0=testRuntimeClasspath
            demo:unmapped-lock:2.0=pluginRuntimeClasspath
            demo:unmapped-declaration:2.0=runtimeClasspath
            demo:custom:2.0=customResolvable
            demo:custom:3.0=customOther
        """.trimIndent())

        ProjectModelBuilder().use { builder ->
            val result = builder.build(workspace)
            val model = requireNotNull(result.model)
            assertEquals(ModelStatus.COMPLETE, result.summary.status, model.parseErrors.toString())
            val (conflict, unmappedLock, unmappedDeclaration, custom) = model.gradle.dependencies
            assertNull(conflict.resolvedVersion)
            assertTrue(conflict.unresolvedReason.orEmpty().contains("несколько версий"))
            assertNull(unmappedLock.resolvedVersion)
            assertTrue(unmappedLock.unresolvedReason.orEmpty().contains("применимость конфигураций"))
            assertNull(unmappedDeclaration.resolvedVersion)
            assertTrue(unmappedDeclaration.unresolvedReason.orEmpty().contains("применимость конфигураций"))
            assertEquals("2.0", custom.resolvedVersion)
            assertNull(custom.unresolvedReason)
            assertEquals(
                listOf(listOf(1, 2), listOf(4), listOf(5), listOf(6)),
                model.gradle.dependencies.map { dependency ->
                    dependency.resolution.filter { it.path == lockfile }.map { it.line }
                },
            )
        }
    }

    private fun resolve(vararg files: Pair<String, String>): List<codeguard.analyzers.model.DeclaredDependency> {
        files.forEach { (path, text) ->
            workspace.resolve(path).parent?.let(Files::createDirectories)
            Files.writeString(workspace.resolve(path), text.trimIndent())
        }
        return ProjectModelBuilder().use { builder ->
            requireNotNull(builder.build(workspace).model).gradle.dependencies
        }
    }

    private fun List<codeguard.analyzers.model.DeclaredDependency>.named(artifact: String) = single { it.artifact == artifact }

    @Test
    fun resolvesSettingsVersionCatalogAtTheLibraryDeclaration() {
        val deps = resolve(
            "settings.gradle.kts" to """
                dependencyResolutionManagement {
                    versionCatalogs {
                        create("libs") {
                            version("jv", "1.13.1")
                            library("jsoup", "org.jsoup", "jsoup").versionRef("jv")
                            library("mybatis", "org.mybatis:mybatis:3.5.5")
                            library("guava", "com.google.guava", "guava").version { strictly("33.0.0") }
                            library("bom-managed", "org.demo", "managed")
                        }
                    }
                }
            """,
            "build.gradle.kts" to """
                dependencies {
                    implementation(libs.jsoup)
                    implementation(libs.mybatis)
                    implementation(libs.guava)
                    implementation(libs.bom.managed)
                    implementation(libs.missing)
                }
            """,
        )
        assertEquals("1.13.1", deps.named("jsoup").resolvedVersion)
        assertEquals(Location("settings.gradle.kts", 5), deps.named("jsoup").declaredAt)
        assertEquals("3.5.5", deps.named("mybatis").resolvedVersion)
        assertEquals(Location("settings.gradle.kts", 6), deps.named("mybatis").declaredAt)
        assertEquals("33.0.0", deps.named("guava").resolvedVersion)
        assertNull(deps.named("managed").resolvedVersion)
        assertTrue(Location("build.gradle.kts", 2) in deps.named("jsoup").resolution)
        assertTrue(Location("settings.gradle.kts", 4) in deps.named("jsoup").resolution)
        assertEquals(4, deps.size)
    }

    @Test
    fun constraintPinsDeclaredAndTransitiveDependencies() {
        val deps = resolve("build.gradle.kts" to """
            dependencies {
                implementation("org.declared:lib")
                implementation("org.versioned:lib:1.0")
                constraints {
                    implementation("org.declared:lib:2.5") { because("pin") }
                    implementation("org.transitive:lib:3.1")
                    implementation("org.range:lib:[1.0,2.0)")
                }
            }
        """)
        val declared = deps.single { it.group == "org.declared" }
        assertEquals("2.5", declared.resolvedVersion)
        assertEquals(Location("build.gradle.kts", 5), declared.declaredAt)
        assertEquals("3.1", deps.single { it.group == "org.transitive" }.resolvedVersion)
        assertEquals(Location("build.gradle.kts", 6), deps.single { it.group == "org.transitive" }.declaredAt)
        assertEquals("1.0", deps.single { it.group == "org.versioned" }.resolvedVersion)
        assertNull(deps.single { it.group == "org.range" }.resolvedVersion)
    }

    @Test
    fun usesDefaultOfAbsentPropertyOnlyWhenNotDefined() {
        val deps = resolve(
            "build.gradle.kts" to """
                val a = (project.findProperty("aVer") as String?) ?: "1.1"
                val b: String = project.findProperty("bVer")?.toString() ?: "2.2"
                val c = (findProperty("cVer") ?: "3.3").toString()
                val d = providers.gradleProperty("dVer").getOrElse("4.4")
                val e = unknownCall() ?: "5.5"
                dependencies {
                    implementation("demo:a:${'$'}a")
                    implementation("demo:b:${'$'}b")
                    implementation("demo:c:${'$'}c")
                    implementation("demo:d:${'$'}d")
                    implementation("demo:e:${'$'}e")
                }
            """,
            "gradle.properties" to "bVer=9.9\n",
        )
        assertEquals("1.1", deps.named("a").resolvedVersion)
        assertEquals("9.9", deps.named("b").resolvedVersion)
        assertEquals("3.3", deps.named("c").resolvedVersion)
        assertEquals("4.4", deps.named("d").resolvedVersion)
        assertNull(deps.named("e").resolvedVersion)
    }

    @Test
    fun resolvesStrictlyVersionBlockAndExtraSet() {
        val deps = resolve("build.gradle.kts" to """
            extra.set("pdfVersion", "2.0.22")
            dependencies {
                implementation("com.google.code.gson:gson") {
                    version { strictly("2.8.8") }
                }
                implementation("demo:prefer") { version { prefer("1.5") } }
                implementation("demo:range") { version { strictly("[1.0,2.0)") } }
                implementation("org.apache.pdfbox:pdfbox:${'$'}{extra["pdfVersion"]}")
                implementation("demo:prop:${'$'}{property("pdfVersion")}")
            }
        """)
        assertEquals("2.8.8", deps.named("gson").resolvedVersion)
        assertEquals("1.5", deps.named("prefer").resolvedVersion)
        assertNull(deps.named("range").resolvedVersion)
        assertEquals("2.0.22", deps.named("pdfbox").resolvedVersion)
        assertEquals("2.0.22", deps.named("prop").resolvedVersion)
    }

    @Test
    fun readsApiDependenciesOfSubprojectBuildFiles() {
        val deps = resolve(
            "settings.gradle.kts" to "include(\":client\")\n",
            "client/build.gradle.kts" to """
                plugins { `java-library` }
                dependencies {
                    api("org.apache.commons:commons-lang3:3.12.0")
                }
            """,
        )
        assertEquals("3.12.0", deps.named("commons-lang3").resolvedVersion)
        assertEquals(Location("client/build.gradle.kts", 3), deps.named("commons-lang3").declaredAt)
    }
}
