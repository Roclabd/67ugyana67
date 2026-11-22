package workflow.analyzers.sca

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class QualifierVersionsTest {
    private fun v(text: String) = requireNotNull(NumericVersion.parseDependency(text), { text })

    private fun range(upper: String, lower: String? = null) =
        VersionRange(lower?.let(NumericVersion::requireNumeric), true, NumericVersion.requireNumeric(upper), false)

    @Test
    fun jreAndAndroidVersionsCompareByNumericComponents() {
        assertTrue(v("31.1-jre") in range("32.0.0"))
        assertTrue(v("31.1-android") in range("32.0.0"))
        assertFalse(v("32.0.1-jre") in range("32.0.0"))
        assertFalse(v("32.0.0-jre") in range("32.0.0"))
        assertTrue(v("31.1-jre") < v("32.0.0-android"))
        assertTrue(v("31.1-jre") > NumericVersion.requireNumeric("31.1"))
    }

    @Test
    fun releaseQualifiersEqualPlainRelease() {
        for (suffix in listOf(".RELEASE", ".Final", ".GA", "-RELEASE")) {
            assertEquals(0, v("5.3.20$suffix").compareTo(NumericVersion.requireNumeric("5.3.20")), suffix)
        }
        assertTrue(v("5.3.20.RELEASE") in range("5.3.21"))
        assertFalse(v("5.3.21.RELEASE") in range("5.3.21"))
    }

    @Test
    fun preReleasesStayUnresolved() {
        for (text in listOf("2.0.0-RC1", "2.0.0.M3", "2.0.0-beta.2", "2.0.0-alpha", "2.8.9-RC1")) {
            assertNull(NumericVersion.parseDependency(text), text)
        }
    }

    @Test
    fun snapshotsAndUnknownQualifiersStayUnresolved() {
        for (text in listOf("1.0.0-SNAPSHOT", "1.14.1-preview", "1.0-foo", "1.+", "")) {
            assertNull(NumericVersion.parseDependency(text), text)
        }
        assertEquals("1.2.3", v("1.2.3").text)
        assertEquals("31.1", v("31.1-jre").text)
    }
}
