// Статическая проверка качества кода (Kotlin, Python, JavaScript). Отдельный модуль: не входит в анализаторы безопасности.
// Kotlin — PSI (kotlin-compiler-embeddable, разрешённый парсер); Python и JavaScript — собственные лексеры и правила.
plugins {
    kotlin("jvm")
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":backend:engine"))
    implementation("org.jetbrains.kotlin:kotlin-compiler-embeddable:2.2.21")
    implementation("org.springframework:spring-context")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
