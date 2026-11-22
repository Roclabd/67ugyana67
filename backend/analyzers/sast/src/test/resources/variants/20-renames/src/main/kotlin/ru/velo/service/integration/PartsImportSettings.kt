package ru.velo.service.integration

internal class PartsImportSettings {
    private val legacyImportPassword = "placeholder-value"

    fun headersForLocalImport(): Map<String, String> =
        mapOf("X-Import-Password" to legacyImportPassword)
}
