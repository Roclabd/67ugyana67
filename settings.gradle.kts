rootProject.name = "codeguard"

listOf("app", "engine", "nodes", "analyzers", "ai", "quality").forEach { module ->
    val directory = file("backend/$module")
    // C and D own these builds. Include them as soon as they supply a build script.
    if (module !in setOf("analyzers", "ai", "quality") || directory.resolve("build.gradle.kts").isFile) {
        include(":backend:$module")
    }
}

val sastDirectory = file("backend/analyzers/sast")
if (sastDirectory.resolve("build.gradle.kts").isFile) {
    include(":sast")
    project(":sast").projectDir = sastDirectory
}
