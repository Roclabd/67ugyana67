"""Static sources with synthetic credentials and benign controls."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from generate import Variant


def properties_secrets(variant: Variant) -> Variant:
    path = "src/main/resources/application-desk.properties"
    variant.add_file(path, """
        desk.oauth.client-secret : fixture-desk-k72t-m4pc
        desk.oauth.api-key = ${DESK_API_KEY}
        desk.storage.password = changeme
    """)
    variant.secret("desk-client-secret", "configuration-token", path, "client-secret")
    variant.secret("desk-env-reference", "api-key", path, "api-key", control=True)
    variant.secret("desk-placeholder", "password", path, "password", control=True)
    return variant


def gradle_property_secrets(variant: Variant) -> Variant:
    path = "gradle.properties"
    variant.add_file(path, """
        publishingPassword=fixture-publishing-r8cz-n72p
        signingApiKey=${SIGNING_API_KEY}
    """)
    variant.secret("literal-publishing-password", "password", path, "publishingPassword")
    variant.secret("signing-env-reference", "api-key", path, "signingApiKey", control=True)
    return variant


def compose_secrets(variant: Variant) -> Variant:
    path = "docker-compose.yml"
    variant.add_file(path, """
        services:
          catalog:
            image: fixture-catalog:local
            environment:
              SERVICE_API_KEY: fixture-compose-x3tj-4kd8
              SERVICE_PASSWORD: ${SERVICE_PASSWORD}
          metrics:
            image: fixture-metrics:local
            environment:
              - METRICS_PASSWORD=fixture-compose-f87m-q2vb
              - METRICS_TOKEN
              - METRICS_API_KEY=${METRICS_API_KEY}
    """)
    variant.secret("compose-mapping-secret", "api-key", path, "SERVICE_API_KEY")
    variant.secret("compose-mapping-env-reference", "password", path, "SERVICE_PASSWORD", control=True)
    variant.secret("compose-list-secret", "password", path, "METRICS_PASSWORD")
    variant.secret("compose-list-inherited", "configuration-token", path, "METRICS_TOKEN", control=True)
    variant.secret("compose-list-env-reference", "api-key", path, "METRICS_API_KEY", control=True)
    return variant


def catalog_secrets(variant: Variant) -> Variant:
    path = "gradle/libs.versions.toml"
    variant.add_file(path, """
        [versions]
        publishing-api-key = 'fixture-catalog-zh73-c9tm'
        publishing-password = "${PUBLISHING_PASSWORD}"
        jwt = "0.12.6"

        [libraries]
        jwt-library = { module = "io.jsonwebtoken:jjwt-api", version.ref = "jwt" }
    """)
    variant.secret("catalog-api-key", "api-key", path, "publishing-api-key")
    variant.secret("catalog-env-reference", "password", path, "publishing-password", control=True)
    variant.secret("catalog-version-alias", "configuration-token", path, 'jwt =', control=True)
    return variant


def kotlin_object_secrets(variant: Variant) -> Variant:
    path = "src/main/kotlin/lab/vault/VaultDefaults.kt"
    variant.add_file(path, """
        package lab.vault

        object VaultDefaults {
            private const val archivePassword = "fixture-vault-w7qr-m52t"
            val runtimeToken: String? = System.getenv("VAULT_RUNTIME_TOKEN")
        }
    """)
    variant.secret("object-password", "password", path, "archivePassword")
    variant.secret("object-env-reference", "configuration-token", path, "runtimeToken", control=True)
    return variant


def kotlin_companion_secrets(variant: Variant) -> Variant:
    path = "src/main/kotlin/lab/gateway/GatewayClient.kt"
    variant.add_file(path, """
        package lab.gateway

        class GatewayClient {
            companion object {
                private const val gatewayApiKey = "fixture-gateway-p64w-b9tf"
                private const val gatewayPassword = "changeme"
            }
        }
    """)
    variant.secret("companion-api-key", "api-key", path, "gatewayApiKey")
    variant.secret("companion-placeholder", "password", path, "gatewayPassword", control=True)
    return variant


def kotlin_value_secrets(variant: Variant) -> Variant:
    path = "src/main/kotlin/lab/imports/ImportSettings.kt"
    variant.add_file(path, r"""
        package lab.imports

        import org.springframework.beans.factory.annotation.Value

        class ImportSettings(
            @Value("\${X:fixture-import-f97c-k3wx}")
            private val importPassword: String,
            @Value("\${IMPORT_API_KEY}")
            private val importApiKey: String,
        )
    """)
    variant.secret("spring-literal-default", "secret-fallback", path, "fixture-import-")
    variant.secret("spring-env-reference", "secret-fallback", path, "IMPORT_API_KEY", control=True)
    return variant


def test_env_secrets(variant: Variant) -> Variant:
    path = "src/test/.env"
    variant.add_file(path, """
        # Synthetic values for the scanner fixture
        TEST_API_KEY='fixture-test-env-h4vz-n65p'
        TEST_PASSWORD=${TEST_PASSWORD}
        TEST_TOKEN=changeme
    """)
    variant.secret("test-env-advisory", "api-key", path, "TEST_API_KEY=")
    variant.secret("test-env-reference", "password", path, "TEST_PASSWORD=", control=True)
    variant.secret("test-env-placeholder", "configuration-token", path, "TEST_TOKEN=", control=True)
    variant.attention.append({"path": path, "line": variant.line_of(path, "TEST_API_KEY="),
                              "rule": "secret.api-key", "reason": "test-source"})
    return variant


def credential_url(variant: Variant) -> Variant:
    path = "src/main/resources/application-storage.properties"
    variant.add_file(path, """
        database.url=jdbc:postgresql://fixture-user:synthetic-7qm4-fake@db.invalid/example
        database.replica=jdbc:postgresql://fixture-user@db.invalid/example
        database.reporting=jdbc:postgresql://fixture-user:${DB_PASSWORD}@db.invalid/example
    """)
    variant.secret("literal-url-password", "password", path, "database.url")
    variant.secret("url-without-password", "password", path, "database.replica", control=True)
    variant.secret("url-env-password", "password", path, "database.reporting", control=True)
    return variant


def pem_private_key(variant: Variant) -> Variant:
    path = "src/main/resources/fixture.pem"
    variant.add_file(path, """
        -----BEGIN PRIVATE KEY-----
        c3ludGhldGljLW5vdC1hLXZhbGlkLWtleQ==
        -----END PRIVATE KEY-----
        -----BEGIN PUBLIC KEY-----
        c3ludGhldGljLW5vdC1hLXZhbGlkLWtleQ==
        -----END PUBLIC KEY-----
    """)
    variant.secret("synthetic-private-key", "configuration-token", path, "BEGIN PRIVATE KEY")
    variant.secret("public-key-control", "configuration-token", path, "BEGIN PUBLIC KEY", control=True)
    return variant


def encoded_secret(variant: Variant) -> Variant:
    path = "src/main/kotlin/lab/fixture/EncodedDefaults.kt"
    variant.add_file(path, """
        package lab.fixture

        object EncodedDefaults {
            const val gatewayApiKey = "Zml4dHVyZS1vbmx5LW5vdC1hLXJlYWwta2V5"
            const val encodedLabel = "cHVibGljLWxhYmVs"
        }
    """)
    variant.secret("encoded-literal-api-key", "api-key", path, "gatewayApiKey")
    variant.secret("encoded-public-label", "api-key", path, "encodedLabel", control=True)
    return variant


def xml_secret(variant: Variant) -> Variant:
    path = "src/main/resources/logback.xml"
    variant.add_file(path, """
        <configuration>
          <property name="collectorApiKey" value="fixture-xml-n3c9-k8s2"/>
          <property name="collectorPassword" value="${COLLECTOR_PASSWORD}"/>
        </configuration>
    """)
    variant.secret("xml-logback-key", "api-key", path, "collectorApiKey")
    variant.secret("xml-logback-env", "password", path, "collectorPassword", control=True)
    path = "pom.xml"
    variant.add_file(path, """
        <project>
          <properties>
            <deploymentPassword>fixture-pom-r4m8-w2n5</deploymentPassword>
            <deploymentApiKey>${env.DEPLOYMENT_API_KEY}</deploymentApiKey>
          </properties>
        </project>
    """)
    variant.secret("pom-password", "password", path, "<deploymentPassword>")
    variant.secret("pom-api-key-env", "api-key", path, "<deploymentApiKey>", control=True)
    return variant
