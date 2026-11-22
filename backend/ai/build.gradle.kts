// AI-слой: LLM объясняет и группирует уже найденное анализаторами.
// Провайдер — любой OpenAI-совместимый API (Groq, OpenRouter, Ollama, vLLM): переключение настройками.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
}

dependencies {
    implementation(project(":sast"))
    // Ноды «ai.explain» и генератор сценария для движка: SPI (engine) и ProjectModel (модуль C).
    // Версии Jackson и Spring — из BOM Spring Boot, который engine отдаёт как api-платформу.
    implementation(project(":backend:analyzers"))
    implementation("org.springframework:spring-context")
    // GET/PUT /api/settings/llm — переключение провайдера с экрана настроек.
    implementation("org.springframework:spring-web")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    testImplementation(kotlin("test"))
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

val repoRoot = projectDir.resolve("../..").normalize()

tasks.test {
    useJUnitPlatform()
    systemProperty("codeguard.repoRoot", repoRoot.absolutePath)
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

// Живой прогон: ./gradlew :backend:ai:explain --args="<каталог проекта>" (нужны LLM_BASE_URL, LLM_MODEL, при необходимости LLM_API_KEY)
tasks.register<JavaExec>("explain") {
    group = "application"
    description = "SAST + объяснения LLM на каталоге проекта"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("ru.codeguard.ai.cli.MainKt")
    workingDir = repoRoot
}
