plugins {
    kotlin("jvm")
    `java-library`
}

kotlin { jvmToolchain(21) }

dependencies {
    api(platform("org.springframework.boot:spring-boot-dependencies:3.5.8"))
    api("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.networknt:json-schema-validator:1.5.9")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
