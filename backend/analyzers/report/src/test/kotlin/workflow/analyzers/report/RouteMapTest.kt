package workflow.analyzers.report

import codeguard.analyzers.model.Endpoint
import codeguard.analyzers.model.Location
import codeguard.analyzers.model.ProjectModelBuilder
import codeguard.analyzers.model.SecurityRule
import codeguard.analyzers.model.SpringModel
import workflow.analyzers.CoverageRule
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.writeText

class RouteMapTest {
    @Test
    fun createsStableRouteArtifactWithTableOwnership() {
        val root = Path.of(System.getProperty("training.project"))
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(root).model)
            val result = routeMap(model)
            val coverage = routeMapCoverage(model)
            val coverageRules = coverage["rules"] as List<*>
            val ruleIds = coverageRules.map { (it as CoverageRule).id }
            assertEquals(listOf("route-map.spring-access-policy", "route-map.data-access-path", "route-map.owner-columns"), ruleIds)
            assertEquals(ruleIds, coverage["rulesApplied"])
            val rows = result.path("routes")
            assertEquals(6, rows.size())
            val expectedTables = mapOf(
                "/api/pickup/export" to setOf("repair_ticket", "pickup_slot"),
                "/api/customer/tickets/{ticketId}" to setOf("repair_ticket"),
            )
            for ((path, expected) in expectedTables) {
                val row = rows.single { it.path("method").asText() == "GET" && it.path("path").asText() == path }
                assertEquals("located", row.path("tableEvidence").asText(), path)
                val tables = row.path("tables").associateBy { it.path("name").asText() }
                assertEquals(expected, tables.keys, path)
                val ticket = tables.getValue("repair_ticket")
                assertTrue(ticket.path("schemaKnown").asBoolean(), path)
                assertTrue(ticket.path("ownerColumns").any { it.asText() == "customer_id" }, path)
            }
            val catalogue = rows.single { it.path("method").asText() == "GET" &&
                it.path("path").asText() == "/api/catalog/services" }
            assertEquals("located", catalogue.path("tableEvidence").asText())
            assertTrue(catalogue.path("tables").isArray)
            assertEquals(0, catalogue.path("tables").size())

            val export = rows.single { it.path("path").asText() == "/api/pickup/export" }
            val role = export.path("subsequentRules").single { it.path("access").asText() == "hasRole" }
            assertEquals("hasRole(\"MECHANIC\")", role.path("accessText").asText())
            val markdown = result.path("markdown").asText()
            assertTrue(markdown.lineSequence().any { "/api/catalog/services" in it && "не используются" in it })
            assertTrue(markdown.contains("hasRole(\"MECHANIC\")"))
            assertFalse(result.toString().contains("SELECT"))
            assertEquals(result, routeMap(model))
        }
    }

    @Test
    fun keepsEmptyTableEvidenceUnresolvedForAnUnknownCall(@TempDir root: Path) {
        root.resolve("Controller.kt").writeText(
            """
            package lab
            import org.springframework.web.bind.annotation.GetMapping
            class Controller {
                @GetMapping("/catalog/current")
                fun current() = listOf("SERVICE_NAMES")
                private fun listOf(value: String) = System.getenv(value)
            }
            """.trimIndent(),
        )
        ProjectModelBuilder().use { builder ->
            val model = requireNotNull(builder.build(root).model)
            val row = routeMap(model).path("routes").single()
            assertEquals("unresolved", row.path("tableEvidence").asText())
            assertEquals(0, row.path("tables").size())
        }
    }

    @Test
    fun keepsOrderAndRequiresReviewWhenAnEarlierRuleCouldMatch() {
        val chain = Location("Security.kt", 1)
        val scope = SecurityRule("GET", listOf("/records/**"), "authenticated", emptyList(),
            Location("Security.kt", 3), "requestMatchers", chain, false)
        val any = scope.copy(method = null, patterns = emptyList(), access = "denyAll", matcher = "anyRequest",
            location = Location("Security.kt", 4))
        val entry = Endpoint("GET", "/records/{id}", "lab.records", emptyList(), emptyList(), emptyList(),
            Location("Endpoint.kt", 1))
        val model = SpringModel(listOf(entry), listOf(scope, any), emptyList(), emptyList(), emptyList())
        val result = routePolicy(model, entry)
        assertEquals(scope, result.rule)
        assertEquals(listOf(any), result.subsequent)

        val oneRecord = scope.copy(patterns = listOf("/records/sample"), location = Location("Security.kt", 2))
        val uncertain = routePolicy(model.copy(securityRules = listOf(oneRecord, scope, any)), entry)
        assertEquals("unresolved", uncertain.status)
    }
}
