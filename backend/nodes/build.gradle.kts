plugins { kotlin("jvm") }
kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":backend:engine"))
    implementation("org.springframework:spring-context")
    implementation("com.google.re2j:re2j:1.8")
    implementation("org.apache.commons:commons-compress:1.28.0")
    implementation("org.apache.httpcomponents.client5:httpclient5")
    implementation("org.eclipse.angus:jakarta.mail:2.0.4")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
