package workflow.analyzers

import codeguard.analyzers.model.ProjectModel
import codeguard.analyzers.model.SourceType
import codeguard.analyzers.model.isVersionCatalog

/** Describes model extraction passes that were applicable to this snapshot. */
internal object ProjectModelRuleCatalog {
    private val rules = listOf(
        CoverageRule(
            "model.kotlin.symbol-index",
            "Индекс Kotlin-объявлений и вызовов",
            "Разбирает Kotlin-файлы в PSI и связывает объявления с разрешимыми вызовами внутри проекта; внешние и неоднозначные вызовы остаются неразрешёнными.",
        ),
        CoverageRule(
            "model.spring.web-security",
            "Spring-маршруты и правила доступа",
            "Извлекает Kotlin-декларации маршрутов, параметры и источники идентичности, method security, порядок правил authorizeHttpRequests и web.ignoring().",
        ),
        CoverageRule(
            "model.spring.cors",
            "Spring CORS-конфигурация",
            "Извлекает статически распознаваемые origins, credentials, методы и пути из известных Spring CORS-конфигураций.",
        ),
        CoverageRule(
            "model.spring.data-access",
            "Spring-доступ к данным",
            "Извлекает распознаваемые Kotlin-методы доступа к данным и сведения о SQL-таблицах и условиях; динамические формы могут остаться неизвестными.",
        ),
        CoverageRule(
            "model.configuration-values",
            "Значения конфигурации",
            "Извлекает пары ключ–значение из YAML, properties, env и каталогов версий с привязкой к файлу и строке.",
        ),
        CoverageRule(
            "model.gradle-dependencies",
            "Объявленные Gradle-зависимости",
            "Извлекает явные Gradle-зависимости и определяет версии по объявлениям, свойствам, каталогу версий, lockfile и встроенным таблицам Spring Boot BOM.",
        ),
        CoverageRule(
            "model.database-schema",
            "Схема таблиц и колонок владельца",
            "Собирает распознаваемые таблицы и owner-колонки из schema.sql, Flyway SQL, Liquibase YAML/XML и JPA-сущностей.",
        ),
    ).associateBy(CoverageRule::id)

    private val configurationTypes = setOf(SourceType.YAML, SourceType.PROPERTIES, SourceType.ENV)
    private val gradleMetadata = setOf("gradle.properties", "gradle.lockfile")
    private val schemaTypes = setOf(SourceType.SQL, SourceType.XML, SourceType.YAML, SourceType.KOTLIN)

    fun applied(model: ProjectModel): List<CoverageRule> {
        val files = model.files
        val applied = buildList {
            if (model.kotlin.isNotEmpty()) add("model.kotlin.symbol-index")
            if (model.kotlin.keys.any { !it.endsWith(".gradle.kts") }) {
                add("model.spring.web-security")
                add("model.spring.cors")
                add("model.spring.data-access")
            }
            if (files.any { it.type in configurationTypes || isVersionCatalog(it.path) }) {
                add("model.configuration-values")
            }
            if (files.any { file ->
                    val name = file.path.substringAfterLast('/')
                    name.endsWith(".gradle.kts") || name in gradleMetadata || isVersionCatalog(file.path)
                }) {
                add("model.gradle-dependencies")
            }
            if (files.any { it.type in schemaTypes }) {
                add("model.database-schema")
            }
        }
        return applied.mapNotNull(rules::get)
    }
}
