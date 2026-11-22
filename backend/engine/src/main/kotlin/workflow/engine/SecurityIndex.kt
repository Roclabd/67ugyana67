package workflow.engine

fun securityIndex(counts: Map<String, Int>): Int =
    (100 - 8 * (counts["CRITICAL"] ?: 0) - 2 * (counts["HIGH"] ?: 0) -
        (counts["MEDIUM"] ?: 0) - Math.ceilDiv(counts["LOW"] ?: 0, 2)).coerceAtLeast(0)
