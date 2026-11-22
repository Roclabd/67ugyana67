package ru.codeguard.ai.context

import java.security.MessageDigest
import java.text.Normalizer

/**
 * Защита от prompt injection: сканируемый репозиторий — недоверенный. Всё, что из него попадает в промпт
 * (пути, фрагменты кода, строковые литералы, README, описания), проходит через [clean]:
 *  - управляющие, нулевой ширины и bidi-символы удаляются;
 *  - длина ограничивается;
 *  - ролевые маркеры («system:», «assistant:», «<|im_start|>», «[INST]») и поддельные ограждения (```, ~~~) обезвреживаются —
 *    в том числе записанные омоглифами («ѕystem») и с невидимыми символами внутри.
 * Дополнительно данные передаются JSON-значениями внутри блока с границей, зависящей от данных ([boundary]).
 */
object PromptGuard {
    const val MAX_PATH = 300
    const val MAX_LINE = 200

    /** Символы кириллицы/греческого, похожие на латиницу → латиница (только для поиска маркеров; 1 символ → 1 символ). */
    private val CONFUSABLES: Map<Char, Char> = mapOf(
        'ѕ' to 's', 'с' to 'c', 'а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'х' to 'x', 'у' to 'y', 'і' to 'i', 'ј' to 'j',
        'ԁ' to 'd', 'ԛ' to 'q', 'ѵ' to 'v', 'һ' to 'h', 'к' to 'k', 'м' to 'm', 'т' to 't', 'н' to 'h', 'в' to 'b',
        'ο' to 'o', 'α' to 'a', 'ε' to 'e', 'ι' to 'i', 'ν' to 'v', 'τ' to 't', 'ѡ' to 'w',
        'А' to 'A', 'С' to 'C', 'Е' to 'E', 'О' to 'O', 'Р' to 'P', 'Х' to 'X', 'Ѕ' to 'S', 'І' to 'I', 'Т' to 'T', 'М' to 'M', 'Н' to 'H', 'К' to 'K', 'В' to 'B',
    )

    private val INVISIBLE = Regex("[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF\\uFFF9-\\uFFFB]")
    private const val ROLE_WORDS = "system|assistant|user|human|developer|tool|instruction|instructions"
    private const val ROLE_WORDS_RU = "систем\\p{L}*|ассистент|пользователь|разработчик|инструкци\\p{L}*"
    private val ROLE_LINE = Regex("(?im)^([ \\t>*#\\-]*)($ROLE_WORDS)(\\s*[:：])")
    private val ROLE_ANY = Regex("(?i)(?<![\\p{L}\\p{N}_.])($ROLE_WORDS)(\\s*[:：])")
    private val ROLE_LINE_RU = Regex("(?im)^([ \\t>*#\\-]*)($ROLE_WORDS_RU)(\\s*[:：])")
    private val ROLE_ANY_RU = Regex("(?i)(?<![\\p{L}\\p{N}_.])($ROLE_WORDS_RU)(\\s*[:：])")
    private val SPECIAL_TOKEN = Regex(
        "<\\|[^|>\\n]{0,40}\\|>|\\[/?INST]|<<\\s*/?SYS\\s*>>|</?\\s*(?:system|assistant|user|im_start|im_end)\\s*>|###\\s*(?:system|assistant|user|instruction)",
        RegexOption.IGNORE_CASE,
    )
    private val FENCE = Regex("`{3,}|~{3,}")
    private val BOUNDARY_LIKE = Regex("(?i)(?:BEGIN|END)[-_ ]?DATA[-_ ]?[0-9a-f]*")

    /** Однострочный вариант: пути, заголовки, описания. */
    fun clean(text: String, max: Int): String =
        neutralize(strip(text).replace('\n', ' ').replace('\r', ' ').replace('\t', ' '), lineStart = false).take(max)

    /** Многострочный вариант: фрагмент кода; каждая строка ограничивается [maxLine]. */
    fun cleanBlock(text: String, maxLine: Int = MAX_LINE): String =
        neutralize(strip(text).replace("\r\n", "\n").replace('\r', '\n'), lineStart = true).split('\n').joinToString("\n") { it.take(maxLine) }

    private fun strip(text: String): String = INVISIBLE.replace(text, "")

    /** Свёртка омоглифов к латинице. */
    fun toLatin(s: String): String = buildString(s.length) { s.forEach { append(CONFUSABLES[it] ?: it) } }

    private val TO_CYR: Map<Char, Char> = CONFUSABLES.entries.filter { it.key.code in 0x400..0x4FF }.associate { (k, v) -> v to k }

    /** Обратная свёртка: латинские двойники → кириллица (для русских фраз с подменой букв). */
    fun toCyrillic(s: String): String = buildString(s.length) { s.forEach { append(TO_CYR[it] ?: it) } }

    private fun nfkc(s: String): String = Normalizer.normalize(s, Normalizer.Form.NFKC).let { if (it.length == s.length) it else s }

    /** Обезвреживает маркеры по свёрнутым копиям; замена — по тем же индексам исходной строки. */
    private fun neutralize(s: String, lineStart: Boolean): String {
        val folded = toLatin(nfkc(s))
        val foldedRu = toCyrillic(nfkc(s))
        val marks = ArrayList<Pair<IntRange, (String) -> String>>()
        ((if (lineStart) ROLE_LINE else ROLE_ANY).findAll(folded).map { it.groups[if (lineStart) 2 else 1]!!.range } +
            (if (lineStart) ROLE_LINE_RU else ROLE_ANY_RU).findAll(foldedRu).map { it.groups[if (lineStart) 2 else 1]!!.range })
            .forEach { r -> marks += r to { orig -> "[$orig]" } }
        FENCE.findAll(folded).forEach { m -> marks += m.range to { orig -> "'".repeat(orig.length) } }
        SPECIAL_TOKEN.findAll(folded).forEach { m ->
            marks += m.range to { orig -> "‹" + orig.replace('<', '(').replace('>', ')').replace('|', '¦').replace('#', '♯').replace('[', '(').replace(']', ')') + "›" }
        }
        BOUNDARY_LIKE.findAll(folded).forEach { m -> marks += m.range to { orig -> orig.replace(Regex("(?i)DATA"), "d4ta") } }
        if (marks.isEmpty()) return s
        val chosen = ArrayList<Pair<IntRange, (String) -> String>>()
        for (mk in marks.sortedBy { it.first.first }) if (chosen.isEmpty() || mk.first.first > chosen.last().first.last) chosen += mk
        val sb = StringBuilder(s)
        for ((r, f) in chosen.reversed()) sb.replace(r.first, r.last + 1, f(s.substring(r.first, r.last + 1)))
        return sb.toString()
    }

    /** Граница блока данных зависит от самих данных (SHA-256): «закрывающий» маркер внутри данных заранее не написать. */
    fun boundary(payload: String): String =
        MessageDigest.getInstance("SHA-256").digest(("codeguard-guard|$payload").toByteArray()).take(8).joinToString("") { "%02x".format(it) }
}
