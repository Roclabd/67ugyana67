import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    kotlin("jvm") version "2.2.21" apply false
    kotlin("plugin.spring") version "2.2.21" apply false
    id("org.springframework.boot") version "3.5.8" apply false
}

allprojects {
    group = "workflow"
    version = "0.1.0-SNAPSHOT"
    repositories { mavenCentral() }
    tasks.withType<Test>().configureEach { useJUnitPlatform() }
}

// :sast supplies the parser classes to :backend:ai. Keep each source in one module.
val standaloneSast = findProject(":sast")
val aggregate = findProject(":backend:analyzers")
if (standaloneSast != null && aggregate != null) {
    val sastRoot = standaloneSast.projectDir.toPath().normalize()
    aggregate.afterEvaluate {
        extensions.getByType<KotlinJvmProjectExtension>().sourceSets.configureEach {
            kotlin.setSrcDirs(kotlin.srcDirs.filterNot { it.toPath().normalize().startsWith(sastRoot) })
        }
    }
}
