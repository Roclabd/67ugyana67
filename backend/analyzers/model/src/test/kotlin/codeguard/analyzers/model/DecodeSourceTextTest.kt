package codeguard.analyzers.model

import java.nio.file.Files
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertEquals

class DecodeSourceTextTest {
    @Test
    fun decodesCommonEncodingsWithoutErrors() {
        val text = "password = \"секрет\""
        assertEquals(text, decodeSourceText(text.toByteArray(Charsets.UTF_8)))
        assertEquals(text, decodeSourceText(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + text.toByteArray(Charsets.UTF_8)))
        assertEquals(text, decodeSourceText(byteArrayOf(0xFF.toByte(), 0xFE.toByte()) + text.toByteArray(Charsets.UTF_16LE)))
        assertEquals(text, decodeSourceText(text.toByteArray(charset("windows-1251"))))
        assertEquals("", decodeSourceText(byteArrayOf(1, 0, 2, 0, 3)))
    }

    @Test
    fun cp1251ConfigIsReadWithoutParseError() {
        val root = Files.createTempDirectory("enc")
        Files.writeString(root.resolve("settings.gradle.kts"), "rootProject.name = \"x\"")
        Files.write(root.resolve("application.properties"), "# Настройки\ndb.password=topsecret123\n".toByteArray(charset("windows-1251")))
        val result = ProjectModelBuilder().use { it.build(root) }
        assertEquals(0, result.summary.parseErrors, result.summary.toString())
    }
}
