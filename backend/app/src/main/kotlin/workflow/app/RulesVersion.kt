package workflow.app

internal fun rulesVersionSignature(versions: Collection<String>): String? {
    // The separator is reserved so each version in the signature identifies one rule set.
    if (versions.isEmpty() || versions.any { it.isBlank() || '+' in it }) return null
    return versions.distinct().sorted().joinToString("+")
}
