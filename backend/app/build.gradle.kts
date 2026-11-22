plugins {
    kotlin("jvm")
    kotlin("plugin.spring")
    id("org.springframework.boot")
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":backend:engine"))
    implementation(project(":backend:nodes"))
    listOf("analyzers", "ai", "quality").mapNotNull { rootProject.findProject(":backend:$it") }
        .filter { it.buildFile.isFile }.forEach {
        runtimeOnly(it)
    }
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml")
    implementation(kotlin("reflect"))
    runtimeOnly("com.h2database:h2")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.processResources {
    from(rootProject.layout.projectDirectory.dir("frontend/dist")) { into("static") }
    from(rootProject.layout.projectDirectory.dir("ci-examples")) {
        include("github-actions.yml", "gitlab-ci.yml")
        into("ci")
    }
}

tasks.bootJar {
    if (providers.gradleProperty("oneClickLaunch").isPresent) {
        archiveFileName.set("codeguard-launch.jar")
    }
    // Kotlin PSI resolves its compiler library as a regular file.
    requiresUnpack("**/kotlin-compiler-embeddable-*.jar")
}

tasks.bootRun {
    workingDir = rootProject.projectDir
}
