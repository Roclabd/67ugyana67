package ru.codeguard.sast

import ru.codeguard.sast.project.SourceText
import kotlin.test.Test
import kotlin.test.assertEquals

/** Номера строк не должны сдвигаться из-за CRLF, одиночного CR и BOM. */
class LineMappingTest {

    private fun lines(raw: String): List<Int> {
        val s = SourceText("A.kt", raw)
        return listOf("a", "b", "c").map { s.lineOf(s.text.indexOf(it)) }
    }

    @Test
    fun `LF`() = assertEquals(listOf(1, 2, 3), lines("a\nb\nc"))

    @Test
    fun `CRLF`() = assertEquals(listOf(1, 2, 3), lines("a\r\nb\r\nc"))

    @Test
    fun `одиночный CR`() = assertEquals(listOf(1, 2, 3), lines("a\rb\rc"))

    @Test
    fun `смешанные переносы`() = assertEquals(listOf(1, 3, 4), lines("a\r\n\rb\nc"))

    @Test
    fun `BOM не сдвигает строки и смещения`() {
        val s = SourceText("A.kt", "﻿a\r\nb\r\nc")
        assertEquals("a\nb\nc", s.text)
        assertEquals(listOf(1, 2, 3), listOf("a", "b", "c").map { s.lineOf(s.text.indexOf(it)) })
    }

    @Test
    fun `символ переноса относится к своей строке`() {
        val s = SourceText("A.kt", "ab\r\ncd")
        assertEquals(1, s.lineOf(1))
        assertEquals(1, s.lineOf(2))
        assertEquals(2, s.lineOf(3))
    }
}
