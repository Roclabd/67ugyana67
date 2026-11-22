package ru.codeguard.sast

import org.junit.jupiter.api.Test
import ru.codeguard.sast.model.SastFinding
import ru.codeguard.sast.project.SastProject
import ru.codeguard.sast.project.SastProjectLoader
import ru.codeguard.sast.project.SourceText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Второй слепой корпус: несколько цепочек безопасности, ключи не по имени id, SQL через пользовательский репозиторий, TrustManager-класс. */
class Blind2Test {
    private fun analyze(vararg files: Pair<String, String>): List<SastFinding> {
        val kotlin = mutableListOf<ru.codeguard.sast.project.KotlinSource>()
        val texts = mutableMapOf<String, SourceText>()
        for ((path, text) in files) {
            if (path.endsWith(".kt")) {
                val (src, errs) = SastProjectLoader.parseKotlin(path, text.trimIndent())
                assertTrue(errs.isEmpty(), "$errs")
                kotlin += src
            } else texts[path] = SourceText(path, text.trimIndent())
        }
        return SastAnalyzer().analyze(SastProject(kotlin, texts, emptyList())).findings
    }

    private fun List<SastFinding>.of(cls: String) = filter { it.sastClass == cls }

    private val imports = """
        import org.springframework.context.annotation.Bean
        import org.springframework.security.config.Customizer
        import org.springframework.security.config.annotation.web.builders.HttpSecurity
        import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
        import org.springframework.security.web.SecurityFilterChain
    """

    private val opsController = "Ops.kt" to """
        import org.springframework.web.bind.annotation.*
        @RestController
        @RequestMapping("/ops")
        class OpsController(private val jdbc: JdbcTemplate) {
            @GetMapping("/drivers/export")
            fun export(): List<Map<String, Any?>> = jdbc.queryForList("select driver_email from reservation")
        }
    """

    // ───── 1. вторая цепочка с securityMatcher ─────

    @Test
    fun scopedChainAnyRequestPermitAllIsFlagged() {
        val r = analyze(opsController, "Sec.kt" to """
            $imports
            class SecurityConfig {
                @Bean
                fun opsChain(http: HttpSecurity): SecurityFilterChain {
                    http
                        .securityMatcher("/ops/**")
                        .authorizeHttpRequests { it.anyRequest().permitAll() }
                    return http.build()
                }
                @Bean
                fun apiChain(http: HttpSecurity): SecurityFilterChain {
                    http.authorizeHttpRequests { it.anyRequest().authenticated() }
                    return http.build()
                }
            }
        """).of("route-authorization")
        assertEquals(1, r.size, r.toString())
        assertEquals("Sec.kt", r.single().path)
        assertTrue(r.single().fragment!!.contains("anyRequest"), r.toString())
    }

    @Test
    fun scopedActuatorChainWithHealthOnlyStaysSilent() {
        val r = analyze(opsController, "Sec.kt" to """
            $imports
            class SecurityConfig {
                @Bean
                fun healthChain(http: HttpSecurity): SecurityFilterChain {
                    http
                        .securityMatcher("/actuator/**")
                        .authorizeHttpRequests {
                            it.requestMatchers("/actuator/health/**").permitAll()
                            it.anyRequest().hasRole("FLEET_ADMIN")
                        }
                    return http.build()
                }
                @Bean
                fun opsChain(http: HttpSecurity): SecurityFilterChain {
                    http.securityMatcher("/ops/**").authorizeHttpRequests { it.anyRequest().hasRole("OPS") }
                    return http.build()
                }
            }
        """).of("route-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    @Test
    fun scopedPublicChainStaysSilent() {
        val r = analyze("Sec.kt" to """
            $imports
            class SecurityConfig {
                @Bean
                fun docsChain(http: HttpSecurity): SecurityFilterChain {
                    http.securityMatcher("/public/**").authorizeHttpRequests { it.anyRequest().permitAll() }
                    return http.build()
                }
            }
        """).of("route-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    // ───── 2. WebSecurityCustomizer.ignoring ─────

    @Test
    fun webSecurityCustomizerIgnoringReports() {
        val r = analyze("Sec.kt" to """
            $imports
            class SecurityConfig {
                @Bean
                fun webSecurityCustomizer(): WebSecurityCustomizer = WebSecurityCustomizer { web ->
                    web.ignoring()
                        .requestMatchers("/api/reports/**")
                }
            }
        """, "Rep.kt" to """
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/reports")
            class ReportController(private val jdbc: JdbcTemplate) {
                @GetMapping("/all")
                fun all(): List<Map<String, Any?>> = jdbc.queryForList("select student_email, value from grade")
            }
        """, "schema.sql" to "create table grade (id bigint primary key, student_email varchar(100), value int);").of("route-authorization")
        assertEquals(1, r.size, r.toString())
    }

    @Test
    fun ignoringStaticAssetsStaysSilent() {
        val r = analyze("Sec.kt" to """
            $imports
            class SecurityConfig {
                @Bean
                fun webSecurityCustomizer(): WebSecurityCustomizer = WebSecurityCustomizer { web ->
                    web.ignoring().requestMatchers("/static/**", "/favicon.ico")
                }
            }
        """).of("route-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    // ───── 3. ключ производного запроса не по имени id ─────

    private val reservationSchema = "schema.sql" to """
        create table reservation (id bigint primary key, reservation_no varchar(24), driver_email varchar(128), vehicle_id bigint);
    """
    private val reservationEntity = "Reservation.kt" to """
        import jakarta.persistence.Entity
        import jakarta.persistence.Id
        @Entity
        class Reservation(@Id var id: Long = 0, var reservationNo: String = "", var driverEmail: String = "", var vehicleId: Long = 0)
    """
    private val reservationRepo = "Repo.kt" to """
        import org.springframework.data.jpa.repository.JpaRepository
        interface ReservationRepository : JpaRepository<Reservation, Long> {
            fun findByReservationNoAndDriverEmail(reservationNo: String, driverEmail: String): Reservation?
            fun deleteByReservationNo(reservationNo: String): Long
        }
    """

    @Test
    fun deleteByNonIdPathKeyWithoutOwnerIsIdor() {
        val r = analyze(reservationSchema, reservationEntity, reservationRepo, "Ctl.kt" to """
            import java.security.Principal
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/reservations")
            class ReservationController(private val reservations: ReservationRepository) {
                @DeleteMapping("/{reservationNo}")
                fun cancel(@PathVariable reservationNo: String, principal: Principal) {
                    log(principal.name, reservationNo)
                    reservations.deleteByReservationNo(reservationNo)
                }
                private fun log(who: String, ref: String) = println("cancel " + ref + " by " + who)
            }
        """, "Sec.kt" to """
            $imports
            class SecurityConfig {
                @Bean
                fun chain(http: HttpSecurity): SecurityFilterChain {
                    http.authorizeHttpRequests { it.anyRequest().authenticated() }
                    return http.build()
                }
            }
        """).of("object-authorization")
        assertEquals(1, r.size, r.toString())
        assertEquals("Ctl.kt", r.single().path)
    }

    @Test
    fun deleteWithOwnerLookupStaysSilent() {
        val r = analyze(reservationSchema, reservationEntity, reservationRepo, "Ctl.kt" to """
            import java.security.Principal
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/reservations")
            class ReservationController(private val reservations: ReservationRepository) {
                @DeleteMapping("/mine/{bookingRef}")
                fun cancelMine(@PathVariable bookingRef: String, principal: Principal) {
                    val own = reservations.findByReservationNoAndDriverEmail(bookingRef, principal.name) ?: throw IllegalStateException()
                    reservations.delete(own)
                }
            }
        """).of("object-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    // ───── 4. PUT с идентификатором в теле ─────

    private val gradeFiles = arrayOf(
        "schema.sql" to "create table grade (id bigint primary key, student_email varchar(128), teacher_email varchar(128), course_code varchar(16), value int);",
        "Grade.kt" to """
            import jakarta.persistence.Entity
            import jakarta.persistence.Id
            @Entity
            class Grade(@Id var id: Long = 0, var studentEmail: String = "", var teacherEmail: String = "", var value: Int = 0)
            data class GradeUpdate(val gradeId: Long, val value: Int)
        """,
        "GradeRepository.kt" to """
            import org.springframework.data.jpa.repository.JpaRepository
            interface GradeRepository : JpaRepository<Grade, Long>
        """,
    )

    @Test
    fun putWithBodyIdWithoutOwnerIsIdor() {
        val r = analyze(*gradeFiles, "GradeController.kt" to """
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/grades")
            class GradeController(private val grades: GradeRepository) {
                @PutMapping
                fun update(@RequestBody body: GradeUpdate): Grade {
                    val grade = grades.findById(body.gradeId).orElseThrow { IllegalStateException() }
                    grade.value = body.value
                    return grades.save(grade)
                }
            }
        """).of("object-authorization")
        assertEquals(1, r.size, r.toString())
    }

    @Test
    fun putWithTeacherCheckStaysSilent() {
        val r = analyze(*gradeFiles, "GradeController.kt" to """
            import java.security.Principal
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/grades")
            class GradeController(private val grades: GradeRepository) {
                @PutMapping("/confirmed")
                fun updateConfirmed(@RequestBody body: GradeUpdate, principal: Principal): Grade {
                    val grade = grades.findById(body.gradeId).orElseThrow { IllegalStateException() }
                    if (grade.teacherEmail != principal.name) throw IllegalStateException("forbidden")
                    grade.value = body.value
                    return grades.save(grade)
                }
            }
        """).of("object-authorization")
        assertTrue(r.isEmpty(), r.toString())
    }

    // ───── 5. SQL в пользовательском репозитории (Spring Data fragment) ─────

    private val vehicleFiles = arrayOf(
        "Search.kt" to """
            interface VehicleSearchRepository {
                fun searchByCity(city: String, sort: String): List<Vehicle>
                fun searchByCitySorted(city: String, sort: SortColumn): List<Vehicle>
            }
            enum class SortColumn(val sql: String) { BATTERY("battery_pct"), PLATE("plate") }
        """,
        "VehicleRepository.kt" to """
            import org.springframework.data.jpa.repository.JpaRepository
            interface VehicleRepository : JpaRepository<Vehicle, Long>, VehicleSearchRepository
        """,
        "VehicleRepositoryImpl.kt" to """
            import jakarta.persistence.EntityManager
            import jakarta.persistence.PersistenceContext
            class VehicleRepositoryImpl : VehicleSearchRepository {
                @PersistenceContext
                private lateinit var em: EntityManager

                override fun searchByCity(city: String, sort: String): List<Vehicle> {
                    val sql = "SELECT * FROM vehicle WHERE city = :city ORDER BY " + sort
                    return em.createNativeQuery(sql, Vehicle::class.java).setParameter("city", city).resultList as List<Vehicle>
                }

                override fun searchByCitySorted(city: String, sort: SortColumn): List<Vehicle> {
                    val ordered = "SELECT * FROM vehicle WHERE city = :city ORDER BY ${'$'}{sort.sql}"
                    return em.createNativeQuery(ordered, Vehicle::class.java).setParameter("city", city).resultList as List<Vehicle>
                }
            }
        """,
    )

    @Test
    fun sortParamThroughCustomRepositoryImplIsSqlInjection() {
        val r = analyze(*vehicleFiles, "VehicleController.kt" to """
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/vehicles")
            class VehicleController(private val vehicles: VehicleRepository) {
                @GetMapping("/nearby")
                fun nearby(@RequestParam city: String, @RequestParam(defaultValue = "battery_pct DESC") sort: String): List<Vehicle> =
                    vehicles.searchByCity(city, sort)
            }
        """).of("sql-injection")
        assertEquals(1, r.size, r.toString())
        assertEquals("VehicleRepositoryImpl.kt", r.single().path)
    }

    @Test
    fun enumWhitelistOrderByStaysSilent() {
        val r = analyze(*vehicleFiles, "VehicleController.kt" to """
            import org.springframework.web.bind.annotation.*
            @RestController
            @RequestMapping("/api/vehicles")
            class VehicleController(private val vehicles: VehicleRepository) {
                @GetMapping("/ranked")
                fun ranked(@RequestParam city: String, @RequestParam by: SortColumn): List<Vehicle> =
                    vehicles.searchByCitySorted(city, by)
            }
        """).of("sql-injection")
        assertTrue(r.isEmpty(), r.toString())
    }

    // ───── 6. TrustManager-класс, установленный в SSLContext ─────

    @Test
    fun trustManagerClassRangeCoversEmptyCheckServerTrusted() {
        val r = analyze("Tls.kt" to """
            import javax.net.ssl.*
            class AcceptAnyServerTrust : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}

                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            class TelematicsHttp {
                private val client: HttpClient by lazy {
                    val ctx = SSLContext.getInstance("TLS")
                    ctx.init(null, arrayOf<TrustManager>(AcceptAnyServerTrust()), null)
                    HttpClient.newBuilder().sslContext(ctx).build()
                }
            }
        """).of("tls-verification")
        assertEquals(1, r.size, r.toString())
        val f = r.single()
        assertTrue(f.line == 2 && (f.endLine ?: f.line) >= 5, "range ${f.line}-${f.endLine}")
        assertTrue(f.evidence.any { it.line == 12 }, "evidence: ${f.evidence}")
    }
}
