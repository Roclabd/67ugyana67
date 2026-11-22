package workflow.engine

/** Форма существительного для числа: 1 файл, 2–4 файла, 5–20 файлов, 21 файл, 11–14 файлов. */
fun ruPlural(n: Int, one: String, few: String, many: String): String {
    val abs = kotlin.math.abs(n.toLong())
    val mod100 = abs % 100
    val mod10 = abs % 10
    return when {
        mod100 in 11..14 -> many
        mod10 == 1L -> one
        mod10 in 2..4 -> few
        else -> many
    }
}

/** «3 файла»: число и существительное в правильной форме. */
fun ruCount(n: Int, one: String, few: String, many: String): String = "$n ${ruPlural(n, one, few, many)}"
