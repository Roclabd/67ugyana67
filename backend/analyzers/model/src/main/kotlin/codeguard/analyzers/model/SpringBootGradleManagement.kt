package codeguard.analyzers.model

internal const val SPRING_BOOT_BOM_COORDINATE = "org.springframework.boot:spring-boot-dependencies"

internal enum class GradlePlatformKind(val notation: String) {
    STANDARD("platform"),
    ENFORCED("enforcedPlatform"),
}

internal enum class GradleBomScope { DIRECT, NESTED, SUBPROJECTS, ALLPROJECTS, BUILDSCRIPT }
internal enum class GradleBomMode { DEFAULT, ENFORCED, CHECK_NATIVE }

internal data class GradleBomImport(
    val configuration: String?,
    val version: String?,
    val coordinate: String?,
    val kind: GradlePlatformKind?,
    val scope: GradleBomScope,
    val declaredAt: Location,
    val evidence: List<Location>,
    val locks: List<GradleLock> = emptyList(),
) {
    val springBoot: Boolean get() = coordinate == SPRING_BOOT_BOM_COORDINATE
    val declarationEvidence: List<Location> get() = listOf(declaredAt) + evidence
}

internal data class GradleVersionOverride(
    val location: Location,
    val configuration: String? = null,
    val coordinate: String? = null,
    val plainDeclaration: Boolean = false,
)

internal data class GradleManagedVersion(
    val version: String?,
    val reason: String?,
    val evidence: List<Location>,
    val springBootBom: SpringBootBomUse? = null,
)

private data class ApplicableBootBom(
    val declaration: GradleBomImport,
    val version: String?,
    val evidence: List<Location>,
    val lockReason: String? = null,
)

internal class SpringBootGradleManagement(
    private val imports: List<GradleBomImport>,
    private val overrides: List<GradleVersionOverride>,
    private val propertyOverrides: List<Location>,
) {
    private val catalogs = mutableMapOf<String, Map<String, String>?>()

    fun resolve(
        coordinate: String,
        configuration: String,
        scope: GradleBomScope,
        mode: GradleBomMode,
    ): GradleManagedVersion? {
        val classpaths = jvmDeclarationClasspaths[configuration].orEmpty().ifEmpty { setOf(configuration) }
        val relevant = imports.filter { bom ->
            val kindMatches = when (mode) {
                GradleBomMode.ENFORCED -> bom.kind == GradlePlatformKind.ENFORCED
                GradleBomMode.DEFAULT -> bom.kind != GradlePlatformKind.ENFORCED || !bom.springBoot
                GradleBomMode.CHECK_NATIVE -> bom.kind != null && (bom.kind != GradlePlatformKind.ENFORCED || !bom.springBoot)
            }
            kindMatches && bom.mayApply(configuration, classpaths, scope)
        }
        val unknownEnforcedCoordinate = mode == GradleBomMode.ENFORCED && relevant.any { it.coordinate == null }
        val boot = relevant.filter(GradleBomImport::springBoot).map { applicableBootBom(it, classpaths, scope) }
        if (boot.isEmpty() && !unknownEnforcedCoordinate) return null

        val competing = relevant.filterNot(GradleBomImport::springBoot)
        val evidence = boot.flatMap(ApplicableBootBom::evidence) + competing.flatMap(GradleBomImport::declarationEvidence)
        if (unknownEnforcedCoordinate) {
            return GradleManagedVersion(null, "Не удалось определить координаты применимого enforcedPlatform", evidence)
        }
        val lockReason = boot.firstNotNullOfOrNull(ApplicableBootBom::lockReason)
        if (lockReason != null) return GradleManagedVersion(null, lockReason, evidence)
        if (boot.any { it.version == null }) {
            return GradleManagedVersion(null, "Не удалось определить точную версию Spring Boot BOM", evidence)
        }
        val unavailable = boot.mapNotNull(ApplicableBootBom::version).distinct().filter { catalog(it) == null }
        if (unavailable.isNotEmpty()) {
            val releases = unavailable.filter(SpringBootBomCatalog::isRelease)
            val detail = if (releases.isEmpty()) "" else releases.joinToString(", ", " (", ")")
            return GradleManagedVersion(null, "Версия Spring Boot BOM отсутствует в локальном каталоге$detail", evidence)
        }
        val managing = boot.mapNotNull { bom -> catalogs[bom.version]?.get(coordinate)?.let { bom to it } }
        val versions = managing.map { it.second }.distinct()
        if (versions.isEmpty()) {
            return if (mode == GradleBomMode.DEFAULT) {
                GradleManagedVersion(null, "Зависимость отсутствует в применимом Spring Boot BOM", evidence)
            } else null
        }
        if (scope != GradleBomScope.DIRECT || managing.any { (bom, _) ->
                bom.declaration.scope != GradleBomScope.DIRECT || classpaths.none { bom.declaration.configuration.appliesOn(it) }
            }
        ) {
            return GradleManagedVersion(null, "Не удалось определить применимость Spring Boot BOM к модулю или конфигурации", evidence)
        }
        if (versions.size > 1) {
            return GradleManagedVersion(null, "Применимые Spring Boot BOM задают разные версии зависимости", evidence)
        }
        if (classpaths.any { classpath -> managing.none { (bom, _) -> bom.declaration.configuration.appliesOn(classpath) } }) {
            return GradleManagedVersion(null, "Spring Boot BOM применим только к части classpath конфигурации $configuration", evidence)
        }
        val matchingOverrides = overrides.filter { override ->
            (mode == GradleBomMode.DEFAULT || !override.plainDeclaration) && (override.coordinate == null || override.coordinate == coordinate) &&
                classpaths.any { override.configuration.appliesOn(it) }
        }.map(GradleVersionOverride::location)
        val matchingProperties = propertyOverrides.takeIf { boot.any { it.declaration.kind == null } }.orEmpty()
        if (competing.isNotEmpty() || matchingOverrides.isNotEmpty() || matchingProperties.isNotEmpty()) {
            return GradleManagedVersion(null, "Версия из Spring Boot BOM может быть переопределена в настройках Gradle",
                evidence + matchingOverrides + matchingProperties)
        }
        val provider = managing.firstOrNull { (bom, _) -> classpaths.all { bom.declaration.configuration.appliesOn(it) } }
            ?: managing.first()
        val bom = provider.first
        return GradleManagedVersion(provider.second, null, evidence,
            SpringBootBomUse(requireNotNull(bom.version), bom.declaration.declaredAt))
    }

    private fun applicableBootBom(bom: GradleBomImport, classpaths: Set<String>, scope: GradleBomScope): ApplicableBootBom {
        val configuration = bom.configuration
        if (configuration == null || bom.scope != GradleBomScope.DIRECT || scope != GradleBomScope.DIRECT) {
            return ApplicableBootBom(bom, bom.version, bom.declarationEvidence)
        }
        val applicableClasspaths = classpaths.filterTo(mutableSetOf()) { configuration.appliesOn(it) }
        if (applicableClasspaths.isEmpty()) return ApplicableBootBom(bom, bom.version, bom.declarationEvidence)
        val locks = selectGradleLocks(bom.locks, configuration, applicableClasspaths)
        val evidence = bom.declarationEvidence + locks.evidence
        val lockedVersion = locks.version
        val hasUnlockedClasspath = applicableClasspaths.any { classpath ->
            locks.applicable.none { configuration in it.configurations || classpath in it.configurations }
        }
        return when {
            lockedVersion != null && lockedVersion != bom.version && hasUnlockedClasspath ->
                ApplicableBootBom(bom, null, evidence,
                    "Запись gradle.lockfile меняет версию Spring Boot BOM только для части применимых classpath")
            lockedVersion != null -> ApplicableBootBom(bom, lockedVersion, evidence)
            locks.applicable.isNotEmpty() -> ApplicableBootBom(bom, null, evidence,
                "Для Spring Boot BOM указано несколько версий в применимых конфигурациях gradle.lockfile")
            locks.unknown.isNotEmpty() -> ApplicableBootBom(bom, null, evidence,
                "Не удалось определить применимость конфигураций gradle.lockfile к Spring Boot BOM")
            else -> ApplicableBootBom(bom, bom.version, evidence)
        }
    }

    private fun catalog(version: String): Map<String, String>? {
        if (version !in catalogs) catalogs[version] = SpringBootBomCatalog.versions(version)
        return catalogs[version]
    }
}

private fun GradleBomImport.mayApply(target: String, classpaths: Set<String>, targetScope: GradleBomScope): Boolean {
    if (scope == GradleBomScope.SUBPROJECTS && targetScope == GradleBomScope.DIRECT) return false
    return classpaths.any { configuration.appliesOn(it) } ||
        configuration !in knownGradleConfigurations || target !in knownGradleConfigurations
}

private fun String?.appliesOn(classpath: String): Boolean =
    this == null || this == classpath || this in platformClasspathDeclarations[classpath].orEmpty()

// A platform inherited by a test classpath can manage test declarations. Test-only platforms do not describe main resolution.
private val platformClasspathDeclarations = jvmClasspathDeclarations + mapOf(
    "testCompileClasspath" to jvmClasspathDeclarations.getValue("testCompileClasspath") + setOf("api", "implementation"),
    "testRuntimeClasspath" to jvmClasspathDeclarations.getValue("testRuntimeClasspath") + setOf("api", "implementation", "runtimeOnly"),
)
