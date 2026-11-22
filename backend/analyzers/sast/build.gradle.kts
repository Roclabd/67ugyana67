// SAST для Kotlin + Spring Boot.
// Собственный анализ поверх Kotlin PSI (kotlin-compiler-embeddable — разрешённый парсер по ТЗ).
// Готовые security-движки и чужие наборы правил не используются.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-compiler-embeddable:2.2.21")
    // Нода «analyzer.sast» для движка: SPI (engine) и ProjectModel (модуль C) — через :backend:analyzers.
    implementation(project(":backend:analyzers"))
    implementation("org.springframework:spring-context")

    testImplementation(kotlin("test"))
    testImplementation("com.networknt:json-schema-validator:1.5.9")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_21) }
}

// Корень репозитория — три уровня вверх от backend/analyzers/sast.
val repoRoot = projectDir.resolve("../../..").normalize()

tasks.test {
    useJUnitPlatform()
    systemProperty("codeguard.repoRoot", repoRoot.absolutePath)
    jvmArgs("-Xss8m")
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

// Прогон на каталоге проекта: ./gradlew :sast:sast --args="<каталог проекта> [out.json]"
tasks.register<JavaExec>("sast") {
    group = "application"
    description = "Запустить SAST на каталоге проекта и вывести JSON в формате авторов набора"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ru.codeguard.sast.cli.MainKt")
    workingDir = repoRoot
}
