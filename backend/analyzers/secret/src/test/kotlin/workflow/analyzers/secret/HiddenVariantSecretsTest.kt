package workflow.analyzers.secret

import codeguard.analyzers.model.ProjectModelBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class HiddenVariantSecretsTest {
    @TempDir lateinit var directory: Path

    private fun scan(files: Map<String, String>): List<SecretCandidate> {
        files.forEach { (name, text) ->
            val file = directory.resolve(name)
            Files.createDirectories(file.parent)
            Files.writeString(file, text)
        }
        return ProjectModelBuilder().use { builder ->
            scanBuiltInSecrets(requireNotNull(builder.build(directory).model)).candidates
        }
    }

    private fun kotlin(body: String) = scan(mapOf("src/main/kotlin/A.kt" to "package p\n\n$body\n"))

    private fun kinds(found: List<SecretCandidate>, value: String) = found.filter { it.value == value }.map { it.kind }

    @Test
    fun secretNamesFromHiddenVariant() {
        val found = kotlin("""
            val masterKey = "mk-Ab12"
            val passphrase = "pp-Cd34"
            val credentials = "svc:pw56"
            val privateKey = "pk-Ef78"
            val clientSecret = "cs-Gh90"
            val signingKey = "sk-Ij12"
            val encryptionKey = "ek-Kl34"
            val keyAlias = "main-alias"
            val privateKeyPath = "/etc/key"
            val privateKeyName = "service"
            val keyFile = "k.pem"
            fun cors(r: Resp) { r.setHeader("Access-Control-Allow-Credentials", "true") }
        """.trimIndent())
        assertTrue(kinds(found, "true").isEmpty())
        for (value in listOf("mk-Ab12", "pp-Cd34", "svc:pw56", "pk-Ef78", "cs-Gh90", "sk-Ij12", "ek-Kl34")) {
            assertEquals(1, kinds(found, value).size, value)
        }
        for (value in listOf("main-alias", "/etc/key", "service", "k.pem")) assertTrue(kinds(found, value).isEmpty(), value)
        assertEquals("password", kinds(found, "pp-Cd34").single())
    }

    @Test
    fun positionalSinks() {
        val found = kotlin("""
            fun f(url: String) {
                Credentials.basic("user", "pw-basic1")
                UsernamePasswordCredentials("user", "pw-upc2".toCharArray())
                DriverManager.getConnection(url, "sa", "pw-jdbc3")
                DriverManagerDataSource(url, "sa", "pw-dmds4")
                DataSourceBuilder.create().password("pw-dsb5").build()
                Algorithm.HMAC256("hm-jwt6")
                SecretKeySpec("hm-key7".toByteArray(), "HmacSHA256")
                Keys.hmacShaKeyFor("hm-key8".toByteArray())
                client.bearerAuth("bt-9")
                BearerTokens("bt-access10", "bt-refresh")
            }
        """.trimIndent())
        for (value in listOf("pw-basic1", "pw-upc2", "pw-jdbc3", "pw-dmds4", "pw-dsb5")) assertEquals("password", kinds(found, value).single(), value)
        for (value in listOf("hm-jwt6", "hm-key7", "hm-key8", "bt-9", "bt-access10")) assertEquals("configuration-token", kinds(found, value).single(), value)
    }

    @Test
    fun positionalSinksResolveConstantsAndIgnoreReferences() {
        val found = scan(mapOf(
            "src/main/kotlin/Consts.kt" to "package p\n\nobject Consts { const val DB = \"pw-const1\" }\n",
            "src/main/kotlin/A.kt" to """
                package p
                fun f(url: String, env: String) {
                    DriverManager.getConnection(url, "sa", Consts.DB)
                    DriverManager.getConnection(url, "sa", System.getenv("DB_PASSWORD"))
                    Credentials.basic("user", "")
                    Credentials.basic("user", "changeme")
                    client.bearerAuth(env)
                }
            """.trimIndent(),
        ))
        assertEquals(listOf("password"), kinds(found, "pw-const1"))
        assertEquals(1, found.size)
    }

    @Test
    fun valueAnnotationLiteralAndBearerHeaderLiteral() {
        val found = kotlin("""
            class C(
                @Value("lit-secret-9") val apiToken: String,
                @Value("${'$'}{app.token}") val other: String,
                @Value("plain") val title: String,
            ) {
                val authorizationHeader = "Bearer abcDEF123"
                val prefixHeader = "Bearer "
            }
        """.trimIndent())
        assertEquals(1, kinds(found, "lit-secret-9").size)
        assertEquals(listOf("configuration-token"), kinds(found, "abcDEF123"))
        assertTrue(kinds(found, "plain").isEmpty())
    }

    @Test
    fun fallbackForms() {
        val found = kotlin("""
            fun env(name: String): String? = System.getenv(name)
            fun f(dotenv: Map<String, String>, v: String?) {
                val a = System.getenv("API_TOKEN").takeUnless { it.isNullOrBlank() } ?: "fb-a1"
                val b = env("API_TOKEN") ?: "fb-b2"
                val c = dotenv["API_TOKEN"] ?: "fb-c3"
                val d = Optional.ofNullable(System.getenv("API_TOKEN")).orElse("fb-d4")
                val e = System.getenv().getOrDefault("API_TOKEN", "fb-e5")
                val g = runCatching { System.getenv("API_TOKEN")!! }.getOrDefault("fb-g6")
                val token = System.getenv("TOKEN")
                val h = if (token != null) token else "fb-h7"
                val i = if (token.isNullOrBlank()) "fb-i8" else token
                val url = System.getenv("BASE_URL") ?: "http://localhost"
                val name = System.getenv("NAME").takeUnless { it.isNullOrBlank() } ?: "fb-none"
            }
        """.trimIndent())
        for (value in listOf("fb-a1", "fb-b2", "fb-c3", "fb-d4", "fb-e5", "fb-g6", "fb-h7", "fb-i8")) {
            assertEquals(listOf("secret-fallback"), kinds(found, value), value)
        }
        assertTrue(kinds(found, "http://localhost").isEmpty())
        assertTrue(kinds(found, "fb-none").isEmpty())
    }

    @Test
    fun recoverableConstructions() {
        val found = kotlin("""
            fun f(client: Client) {
                var t = "rt-aa"
                t += "bb12"
                client.setBearerAuth(t)
                val sb = StringBuilder().apply { append("rt-cc"); append("dd34") }.toString()
                client.setBearerAuth(sb)
                val l = mutableListOf<String>().apply { add("rt-ee"); add("ff56") }.joinToString("")
                client.setBearerAuth(l)
                val r = listOf("rt-", "gg", "78").fold("") { acc, s -> acc + s }
                client.setBearerAuth(r)
                val u = listOf("RT-hh", "90").reduce { acc, s -> acc + s }.lowercase()
                client.setBearerAuth(u)
                val x = "rt-ZZxx12".replace("ZZ", "ii")
                client.setBearerAuth(x)
                var plain = "not-used"
                plain += "x"
                client.other(plain)
            }
        """.trimIndent())
        for (value in listOf("rt-aabb12", "rt-ccdd34", "rt-eeff56", "rt-gg78", "rt-hh90", "rt-iixx12")) {
            assertEquals(listOf("recoverable-token"), kinds(found, value), value)
        }
        assertTrue(found.none { it.value.startsWith("not-used") })
    }

    @Test
    fun dockerfileEnvFilesJsonAndSql() {
        val found = scan(mapOf(
            "Dockerfile" to "FROM x\nENV DB_PASSWORD=Zx9pQw7r\nENV API_TOKEN legacy-tok-12\nARG BUILD_TOKEN=arg-tok-34\nENV PASSWORD=\${'$'}{SECRET_PW}\nENV JAVA_OPTS=-Xmx1g\nENV X_PASSWORD=changeme\n",
            "docker/prod.env" to "DB_PASSWORD=prod-pw-56\nSERVICE_URL=http://x\n",
            "config/credentials.json" to "{\n  \"clientSecret\": \"json-sec-78\",\n  \"name\": \"svc\"\n}\n",
            "db/data.sql" to "INSERT INTO users(login, password, role) VALUES ('admin', 'sql-pw-90', 'ADMIN'), ('bob', 'sql-pw-91', 'U');\n" +
                "INSERT INTO users(login, password) VALUES ('h', '\${'$'}2a\${'$'}10\${'$'}abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz0123456789ab');\n" +
                "INSERT INTO t(name, title) VALUES ('password', 'x');\n",
        ))
        for (value in listOf("Zx9pQw7r", "legacy-tok-12", "arg-tok-34", "prod-pw-56", "json-sec-78", "sql-pw-90", "sql-pw-91")) {
            assertEquals(1, kinds(found, value).size, value)
        }
        assertEquals(2, found.count { it.location.path == "db/data.sql" })
        assertEquals(1, found.count { it.location.path == "db/data.sql" && it.location.line == 1 && it.value == "sql-pw-90" })
        assertTrue(found.none { it.value == "-Xmx1g" || it.value == "http://x" || it.value == "svc" })
        assertNull(found.firstOrNull { it.value == "changeme" })
    }
}
