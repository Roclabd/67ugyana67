# ProjectModel

> Версия 1. Нода «Разбор проекта» принимает снимок через порт типа `WORKSPACE` и строит одну общую модель. Ноды SECRET, SCA и SAST принимают её через порт типа `PROJECT_MODEL`. Типы портов определены в [SPI](node-spi.md).

```kotlin
class ProjectModel(
    val root: Path,
    val files: List<SourceFile>,                 // путь, тип (KOTLIN, KOTLIN_SCRIPT, YAML, PROPERTIES, SQL, LOCKFILE, TOML, MARKDOWN, OTHER), текст, хэш
    val kotlin: Map<String, KtFile>,             // PSI по относительному пути (.kt и .kts)
    val declarations: DeclarationIndex,          // классы, функции, свойства, константы → место
    val calls: CallIndex,                        // вызовы с разрешением в функции проекта, где возможно
    val config: List<ConfigEntry>,               // YAML/properties: key, value, kind (LITERAL / ENV / ENV_WITH_DEFAULT / EMPTY), path, line
    val gradle: GradleModel,
    val spring: SpringModel,
    val sqlSchema: SqlSchema,
    val parseErrors: List<ParseError>            // файл, строка, сообщение → coverage PARTIAL
)

class GradleModel(
    val dependencies: List<DeclaredDependency>,  // только явно объявленные
    val properties: Map<String, Located<String>>,// gradle.properties, extra[], val в скрипте
    val lockfile: Map<String, String>            // group:artifact → версия
)

class DeclaredDependency(
    val configuration: String,                   // implementation, api, runtimeOnly, testImplementation...
    val group: String, val artifact: String,
    val declaredVersion: String?,                // как написано: "1.9", "$archiveFormatVersion", null
    val resolvedVersion: String?,                // из применимого lockfile, объявления или BOM. null → coverage.unresolved
    val unresolvedReason: String?,               // причина, если resolvedVersion отсутствует
    val resolution: List<Location>,              // строка объявления, строка val, строка gradle.properties...
    val declaredAt: Location,
    val springBootBom: SpringBootBomUse?         // релиз таблицы и место подключения, если версия получена из BOM
)

class SpringBootBomUse(val release: String, val declaredAt: Location)

class SpringModel(
    val endpoints: List<Endpoint>,               // HTTP-метод, полный путь (с @RequestMapping класса), функция, параметры с источником
                                                 // (@RequestParam/@PathVariable/@RequestBody/@RequestHeader), источники личности (Principal, Authentication,
                                                 // @AuthenticationPrincipal, @RequestHeader("Authorization") → в какой сервис передан), @PreAuthorize/@Secured
    val securityRules: List<SecurityRule>,       // цепочка authorizeHttpRequests ПО ПОРЯДКУ: метод?, паттерны, доступ (permitAll, authenticated, hasRole..., denyAll), место
    val ignoredPaths: List<Located<String>>,     // web.ignoring()
    val corsConfigs: List<CorsConfig>,           // origins / originPatterns, allowCredentials, методы, пути, место
    val repositories: List<DataAccessMethod>     // методы с SQL: текст запроса, список таблиц, колонки в WHERE, параметризован ли
)

class SqlSchema(val tables: Map<String, Table>)  // колонки; ownerColumns: customer_id, user_id, owner_id, owner...
                                                 // источники: schema.sql, Flyway db/migration/V*.sql, Liquibase YAML/XML, JPA @Entity (@ManyToOne, owner/customerId/userId)
```

## Правила модели

- Все ключи и места в модели, кроме внутреннего `root`, используют путь относительно корня снимка. Разделитель `/`, регистр совпадает с исходным путём. У `Location` есть `path`, `line` и необязательная `endLine`. Границы включительны.
- Строки считаются по исходному файлу с 1. CRLF и LF считаются одним переносом, начальный BOM не сдвигает строки. Хэш файла считается по исходным байтам.
- Ошибка разбора файла записывается в `parseErrors` с путём и причиной. Строка указывается, когда парсер её определил. Модель остальных файлов доступна. Если ошибка мешает анализатору проверить вход, он возвращает `PARTIAL` с записью в `coverage.filesSkipped`. Если модель невозможно построить целиком как объект, нода завершает работу с `FAILED`.
- Данные и деревья PSI доступны анализаторам только для чтения. `ProjectModel` передаётся между нодами внутри процесса. Для SSE и журнала передаются только безопасные метаданные, например количество файлов и число ошибок разбора. Исходники, PSI, абсолютный `root` и значения из `ConfigEntry` остаются внутри процесса.
- Источник зависимостей — явные объявления Gradle. Каталог версий помогает разрешить версию объявления. Версия из `gradle.lockfile` применяется при совпадении конфигурации или для соответствующего classpath стандартного набора исходников JVM. Например, для `implementation` подходят `compileClasspath` и `runtimeClasspath`, а для `testRuntimeOnly` подходит `testRuntimeClasspath`. При отсутствии применимой записи используем точную версию из объявления, если применимость остальных записей и влияние платформ Gradle можно установить статически. Когда применимые записи указывают разные версии или связь с конфигурацией установить нельзя, зависимость сохраняется с `resolvedVersion = null` и причиной для `coverage.unresolved`. `resolution` начинается с места объявления и включает источники, использованные при определении версии.
- Для зависимости без версии модель использует встроенную таблицу точного релиза Spring Boot BOM из Gradle-скрипта модуля. Поддерживаются автоматический импорт при активных плагинах Boot и `io.spring.dependency-management` и явное подключение через `platform` или `enforcedPlatform`. Применимый `enforcedPlatform` может задать версию и для объявления с явной версией. Если рекомендация обычного `platform` расходится с явной версией, итог выбора Gradle остаётся неопределённым. Место и релиз BOM сохраняются в `springBootBom`, место также входит в `resolution`. При отсутствии таблицы, конфликте или неясной области действия причина записывается в `unresolvedReason`. Gradle-скрипты анализируются офлайн как данные.
- Правила Spring Security хранятся в порядке объявления. Модель сохраняет метод, путь и место правила. Если привязка маршрута, правила или запроса к таблице не установлена, соответствующий факт остаётся неизвестным для анализатора.
