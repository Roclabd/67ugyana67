package codeguard.analyzers.model

import java.util.concurrent.ConcurrentHashMap

internal object SpringBootBomCatalog {
    private val releaseVersion = Regex("[0-9]{1,4}(?:\\.[0-9]{1,4}){2}")
    private val tables = ConcurrentHashMap<String, Map<String, String>>()

    fun isRelease(bootVersion: String): Boolean = releaseVersion.matches(bootVersion)

    fun versions(bootVersion: String): Map<String, String>? {
        if (!isRelease(bootVersion)) return null
        tables[bootVersion]?.let { return it }
        val resource = javaClass.getResourceAsStream("/spring-boot-bom/$bootVersion.tsv") ?: return null
        val versions = resource.bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.associate { line ->
                val (coordinate, version) = line.split('\t', limit = 2)
                coordinate to version
            }
        }
        return tables.putIfAbsent(bootVersion, versions) ?: versions
    }
}
