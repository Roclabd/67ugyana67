"""Static examples of Gradle version sources for the defensive SCA suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from generate import Variant


BUILD = "build.gradle.kts"


def extra_versions(variant: Variant) -> Variant:
    variant.add_file(BUILD, """
        extra["codecRelease"] = "2.8.8"
        extra["networkRelease"] = "3.9.0"

        dependencies {
            implementation("com.google.code.gson:gson:${extra["codecRelease"]}")
            implementation("commons-net:commons-net:${extra["networkRelease"]}")
        }
    """)
    variant.dependency("codec-direct-extra", "com.google.code.gson:gson:2.8.8", "gson:")
    variant.dependency("network-direct-extra-fixed", "commons-net:commons-net:3.9.0",
                       "commons-net:", control=True)
    return variant


def catalog_versions(variant: Variant) -> Variant:
    variant.add_file("gradle/libs.versions.toml", """
        [versions]
        text-processing = { strictly = "3.18.0" }

        [libraries]
        archive-io = { module = "commons-io:commons-io", version = { strictly = "2.6" } }
        text-processing = { module = "org.apache.commons:commons-lang3", version.ref = "text-processing" }

        [bundles]
        archive-tools = ["archive-io", "text-processing"]
    """)
    variant.add_file(BUILD, """
        dependencies {
            implementation(libs.bundles.archive.tools)
        }
    """)
    anchor = "libs.bundles.archive.tools"
    variant.dependency("io-catalog-bundle", "commons-io:commons-io:2.6", anchor)
    variant.dependency("lang-catalog-bundle-fixed", "org.apache.commons:commons-lang3:3.18.0",
                       anchor, control=True)
    return variant


def val_versions(variant: Variant) -> Variant:
    variant.add_file(BUILD, """
        val archiveRelease = "1.25.0"

        dependencies {
            val textRelease = "1.10.0"
            implementation("org.apache.commons:commons-compress:$archiveRelease")
            implementation(group = "org.apache.commons", name = "commons-text", version = textRelease)
        }
    """)
    variant.dependency("archive-literal-val", "org.apache.commons:commons-compress:1.25.0",
                       "commons-compress:")
    variant.dependency("text-local-val-fixed", "org.apache.commons:commons-text:1.10.0",
                       'name = "commons-text"', control=True)
    return variant


def property_versions(variant: Variant) -> Variant:
    variant.add_file("gradle.properties", """
        yamlRelease=1.31
        codecRelease=2.8.9
    """)
    variant.add_file(BUILD, """
        val yamlRelease: String by project
        val codecRelease: String by project

        dependencies {
            implementation("org.yaml:snakeyaml:$yamlRelease")
            implementation("com.google.code.gson:gson:$codecRelease")
        }
    """)
    variant.dependency("yaml-project-property", "org.yaml:snakeyaml:1.31", "snakeyaml:")
    variant.dependency("codec-project-property-fixed", "com.google.code.gson:gson:2.8.9",
                       "gson:", control=True)
    return variant


def named_coordinates(variant: Variant) -> Variant:
    variant.add_file(BUILD, """
        dependencies {
            implementation(group = "org.apache.commons", name = "commons-text", version = "1.9")
            implementation(group = "commons-net", name = "commons-net", version = "3.9.0")
        }
    """)
    variant.dependency("named-vulnerable", "org.apache.commons:commons-text:1.9", 'name = "commons-text"')
    variant.dependency("named-fixed", "commons-net:commons-net:3.9.0", 'name = "commons-net"', control=True)
    return variant


def gradle_configurations(variant: Variant) -> Variant:
    variant.add_file(BUILD, """
        dependencies {
            api("org.apache.commons:commons-text:1.9")
            kapt("com.google.code.gson:gson:2.8.8")
            runtimeOnly("commons-net:commons-net:3.8.0")
            runtimeOnly("org.apache.commons:commons-lang3:3.18.0")
        }
    """)
    variant.dependency("api-notation", "org.apache.commons:commons-text:1.9", 'api("')
    variant.dependency("kapt-notation", "com.google.code.gson:gson:2.8.8", 'kapt("')
    variant.dependency("runtime-notation", "commons-net:commons-net:3.8.0", "commons-net:")
    variant.dependency("runtime-fixed", "org.apache.commons:commons-lang3:3.18.0", "commons-lang3:", control=True)
    return variant


def buildsrc_versions(variant: Variant) -> Variant:
    variant.add_file("buildSrc/src/main/kotlin/dependencies/Versions.kt", """
        package dependencies

        object Versions {
            const val text = "1.9"
            const val network = "3.9.0"
        }
    """)
    variant.add_file(BUILD, """
        import dependencies.Versions as LibraryVersions

        dependencies {
            implementation("org.apache.commons:commons-text:${LibraryVersions.text}")
            implementation("commons-net:commons-net:${LibraryVersions.network}")
        }
    """)
    variant.dependency("buildsrc-constant", "org.apache.commons:commons-text:1.9", "commons-text:")
    variant.dependency("buildsrc-fixed", "commons-net:commons-net:3.9.0", "commons-net:", control=True)
    return variant


def convention_versions(variant: Variant) -> Variant:
    convention = "buildSrc/src/main/kotlin/fixture.libraries.gradle.kts"
    variant.add_file(convention, """
        plugins { `java-library` }

        val archiveVersion = "1.25.0"
        dependencies {
            api("org.apache.commons:commons-compress:$archiveVersion")
        }
    """)
    variant.add_file(BUILD, 'plugins { id("fixture.libraries") }')
    variant.dependency("convention-constant", "org.apache.commons:commons-compress:1.25.0",
                       "commons-compress:", path=convention)
    return variant


def platform_lock(variant: Variant) -> Variant:
    variant.add_file(BUILD, """
        dependencies {
            implementation(platform("com.fasterxml.jackson:jackson-bom:2.9.9"))
            implementation("com.fasterxml.jackson.core:jackson-databind")
        }
    """)
    variant.add_file("gradle.lockfile", """
        com.fasterxml.jackson.core:jackson-databind:2.9.9=compileClasspath,runtimeClasspath
    """)
    variant.dependency("bom-locked-dependency", "com.fasterxml.jackson.core:jackson-databind:2.9.9", 'implementation("com.fasterxml.jackson.core:jackson-databind")')
    return variant
