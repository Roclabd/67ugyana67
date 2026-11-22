package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class EmbeddedSecretsTest {
    @TempDir lateinit var directory: Path

    private fun scan(kotlin: String? = null, properties: String? = null): List<Pair<String, Int>> {
        kotlin?.let { Files.writeString(directory.resolve("App.kt"), it.trimIndent()) }
        properties?.let { Files.writeString(directory.resolve("application.properties"), it.trimIndent()) }
        return ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(directory).model)
            scanBuiltInSecrets(model).candidates.map { it.kind to it.location.line }.sortedBy { it.second }
        }
    }

    @Test
    fun comparisonsWithSecretNames() {
        val found = scan("""
            fun f(password: String, pwd: String, apiKey: String, token: String) {
                if (password == "admin123") {}
                if ("admin123" == pwd) {}
                if (pwd.equals("x1")) {}
                if (apiKey == "abc-def-ghi") {}
                if (token == "tok-123456") {}
            }
        """)
        assertEquals(listOf("password", "password", "password", "api-key", "configuration-token"), found.map { it.first })
    }

    @Test
    fun comparisonsNegatives() {
        assertEquals(emptyList<Any>(), scan("""
            fun f(password: String, other: String, mode: String, tokenType: String) {
                if (password == "") {}
                if (password == other) {}
                if (mode == "password") {}
                if (tokenType == "Bearer") {}
                if (password == "changeme") {}
                if (password == "${'$'}{DB_PASSWORD}") {}
            }
        """))
    }

    @Test
    fun mapsAndPropertiesKeyedBySecretName() {
        val found = scan("""
            fun f(props: MutableMap<String, String>, p: java.util.Properties) {
                val a = mapOf("password" to "S3cret!")
                props["password"] = "x9y8"
                props.put("api_key", "key-12345")
                p.setProperty("db.password", "pw-12345")
                p["client.secret"] = "cs-12345"
            }
        """)
        assertEquals(listOf("password", "password", "api-key", "password", "configuration-token"), found.map { it.first })
    }

    @Test
    fun mapsNegatives() {
        assertEquals(emptyList<Any>(), scan("""
            fun f(props: MutableMap<String, String>, v: String) {
                val a = mapOf("name" to "Alice", "password" to v)
                props["password"] = v
                props["password"] = ""
                props.put("title", "hello")
                props.put("password", "YOUR_PASSWORD")
            }
        """))
    }

    @Test
    fun springSecurityUserBuilder() {
        val found = scan("""
            fun f() {
                User.withUsername("u").password("{noop}admin123").roles("A").build()
                User.withUsername("v").password("plain99").build()
                User.withUsername("w").password("{bcrypt}${'$'}2a${'$'}10${'$'}7EqJtq98hPqEX7fNZaFWoOhi5BWd6ez3Ey4CVT0M2OJmbJN2S0zWe").build()
            }
        """)
        assertEquals(listOf("password", "password"), found.map { it.first })
    }

    @Test
    fun urlParametersInKotlin() {
        val found = scan("""
            val a = "jdbc:postgresql://h/db?user=a&password=hunter22"
            val b = "jdbc:sqlserver://h;databaseName=x;password=Hunter22"
            val c = "http://h/x?id=1&pwd=hunter33"
            val d = "http://h/x?access_token=abcdef123456"
            fun f() = java.sql.DriverManager.getConnection("jdbc:mysql://h/db?user=a&password=hunter44")
        """)
        assertEquals(listOf("password", "password", "password", "configuration-token", "password"), found.map { it.first })
    }

    @Test
    fun urlParameterNegatives() {
        assertEquals(emptyList<Any>(), scan("""
            val a = "jdbc:postgresql://h/db?user=a&password=${'$'}{DB_PASSWORD}"
            val b = "http://h/x?id=1&name=bob"
            val c = "http://h/x?password=changeme"
            val d = "http://h/x?token="
            val e = "jdbc:postgresql://h/db?ssl=true"
        """))
    }

    @Test
    fun urlParametersInConfig() {
        val found = scan(properties = """
            spring.datasource.url=jdbc:postgresql://h/db?user=a&password=hunter22
            other.endpoint=http://h/x?access_token=abcdef123456
            safe.url=jdbc:postgresql://h/db?password=${'$'}{PW}
        """)
        assertEquals(listOf("password", "configuration-token"), found.map { it.first })
    }

    @Test
    fun knownTokenShapes() {
        val found = scan("""
            val a = "AKIAIOSFODNN7EXAMPLE"
            val b = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
            val c = "xoxb-123456789012-abcdefghijkl"
            val d = "123456789:AAabcdefghijklmnopqrstuvwxyz0123456"
            val e = "sk_live_abcdefghijklmnop1234"
            val f = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
        """)
        assertEquals(listOf("api-key", "api-key", "api-key", "configuration-token", "api-key", "api-key"), found.map { it.first })
    }

    @Test
    fun tokenShapeNegativesAndSingleFindingPerLine() {
        assertEquals(emptyList<Any>(), scan("""
            val a = "AKIA-not-a-key"
            val b = "ghp_short"
            val c = "sk_test_abcdefghijklmnop1234"
            val d = "hello world"
        """))
        assertEquals(1, scan("""val apiKey = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"""").size)
    }

    @Test
    fun tokenShapeInConfig() {
        val found = scan(properties = "notify.hook=xoxb-123456789012-abcdefghijkl\nnotify.name=hello")
        assertEquals(listOf("api-key"), found.map { it.first })
    }

    @Test
    fun basicAuthLiteral() {
        // dXNlcjpwYXNzMTIz = user:pass123 ; dXNlcjo= = "user:" ; dXNlcjp5b3VyX3Bhc3M= = user:your_pass
        val found = scan("""
            val a = "Basic dXNlcjpwYXNzMTIz"
            val b = "Basic dXNlcjo="
            val c = "Basic bm90LWJhc2U2NA=="
        """)
        assertEquals(listOf("password"), found.map { it.first })
        assertEquals(listOf(1), found.map { it.second })
    }
}
