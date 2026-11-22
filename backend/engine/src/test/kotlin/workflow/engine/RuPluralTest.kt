package workflow.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RuPluralTest {
    @Test fun `forms follow Russian rules`() {
        val expected = mapOf(0 to "файлов", 1 to "файл", 2 to "файла", 4 to "файла", 5 to "файлов", 11 to "файлов", 12 to "файлов",
            14 to "файлов", 20 to "файлов", 21 to "файл", 22 to "файла", 25 to "файлов", 101 to "файл", 111 to "файлов")
        for ((n, word) in expected) assertEquals(word, ruPlural(n, "файл", "файла", "файлов"), "n=$n")
        assertEquals("3 файла", ruCount(3, "файл", "файла", "файлов"))
    }
}
