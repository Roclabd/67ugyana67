plugins {
    kotlin("jvm")
    id("java-library")
}

kotlin {
    jvmToolchain(21)
    sourceSets {
        val modules = listOf("model", "secret", "sca", "report")
        main { kotlin.srcDirs(modules.map { "$it/src/main/kotlin" }) }
        test { kotlin.srcDirs(modules.map { "$it/src/test/kotlin" }) }
    }
}

sourceSets.main {
    resources.srcDir("model/src/main/resources")
    resources.srcDir("report/src/main/resources")
}

dependencies {
    api(project(":backend:engine"))
    api("org.jetbrains.kotlin:kotlin-compiler-embeddable:2.2.21")
    implementation("org.springframework:spring-context")
    implementation("org.yaml:snakeyaml:2.4")
    implementation("org.tomlj:tomlj:1.1.1")
    implementation("com.google.re2j:re2j:1.8")
    implementation("org.apache.pdfbox:pdfbox:3.0.4")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.processResources {
    from(rootProject.layout.projectDirectory.file("fixtures/training/vulnerability-database/vulnerabilities.json")) {
        into("sca")
    }
}

tasks.test {
    systemProperty("training.project", rootProject.file("fixtures/training/sample-project").absolutePath)
}
