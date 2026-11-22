package lab.servicedesk.integration

internal class PartsImportSettings {
    private val legacyImportPassword = "codeguard_parts_H9r4Vm2Kb6Qp"

    fun headersForLocalImport(): Map<String, String> =
        mapOf("X-Import-Password" to legacyImportPassword)
}
