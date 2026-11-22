# SPI ноды

> Реализация v0.1. Утвердить первым делом: от него зависят C и D (ноды анализаторов и AI живут в их модулях).

## Интерфейс

Пакет `workflow.engine` в `:backend:engine`. Модули анализаторов и AI добавляют `implementation(project(":backend:engine"))`. Spring Boot сканирует пакет `workflow` и подпакеты.

```kotlin
interface NodeDefinition {
    val type: String                  // уникально: "trigger.manual", "analyzer.secret", "ai.explain"
    val title: String                 // по-русски, для палитры
    val category: NodeCategory        // TRIGGER, SOURCE, ANALYZER, LOGIC, AI, OUTPUT
    val inputs: List<PortSpec>
    val outputs: List<PortSpec>
    val paramsSchema: JsonNode        // JSON Schema параметров; фронт строит форму по ней
    val secretParams: Set<String> get() = emptySet()
    fun validateParams(params: JsonNode): Boolean = true
    suspend fun run(ctx: NodeContext, input: NodeInput): NodeOutput
}

data class PortSpec(val name: String, val type: PortType, val required: Boolean = true)

enum class PortType { WORKSPACE, PROJECT_MODEL, FINDINGS, REPORT, DECISION, ANY }

interface NodeContext {
    val runId: String
    val nodeId: String
    val params: JsonNode              // уже с подставленными выражениями и расшифрованными секретами
    val workspace: Path?              // рабочая папка запуска (только чтение для анализаторов)
    val trigger: JsonNode            // kind, source, branch, commitSha, scheduledAt
    val coverageStatus: String       // покрытие завершённых анализаторов
    fun redact(message: String): String
    fun log(message: String)          // маскирование секретов — внутри
    fun emitProgress(percent: Int, note: String? = null)
}

data class NodeInput(val ports: Map<String, Any?>)
data class NodeOutput(
    val ports: Map<String, Any?>,     // для if/else: "true" / "false" — активна только одна
    val status: NodeStatus = NodeStatus.SUCCESS,
    val coverage: Any? = null,        // покрытие конкретного анализатора
    val rulesVersion: String? = null  // версия набора правил для CI
)

enum class NodeStatus { PENDING, RUNNING, SUCCESS, PARTIAL, FAILED, SKIPPED }
```

## Правила

- Нода регистрируется как Spring-бин, реестр собирает все `NodeDefinition`; `GET /api/nodes` отдаёт тип, название, категорию, порты, схему параметров.
- Новая нода = один класс, без правок движка и фронта.
- Ноды не обращаются к БД и HTTP-слою платформы напрямую — только через `NodeContext` и свои зависимости.
- Анализаторы читают `workspace` только для чтения; запись — в свою временную папку.
- Ошибка внутри ноды → `FAILED` с сообщением; движок сам решает, продолжать ли (флаг ноды «продолжать при ошибке»).
- Секретные параметры не попадают в `log`, в данные портов, в SSE.

## GraphValidator

`fun validate(workflow: Workflow): List<GraphError>` — известные типы нод; совместимые типы портов (`ANY` совместим со всем); обязательные входы подключены; параметры проходят `paramsSchema`; нет циклов. Используют: сохранение сценария, публикация шаблона (B6), генерация сценария из текста (B7), запуск.

## Выражения в параметрах

`{{findings.count}}`, `{{findings.bySeverity.CRITICAL}}`, `{{run.id}}`, `{{trigger.branch}}`, `{{node.<id>.output.<port>...}}`. Свой безопасный вычислитель путей, без `eval`/`ScriptEngine`.

## Подключение соседних модулей

- C и D регистрируют `NodeDefinition` как `@Component` или через `@Bean`. Ноды сканеров используют типы `analyzer.secret`, `analyzer.sca`, `analyzer.sast`, категорию `ANALYZER`, вход `PROJECT_MODEL` и выход `FINDINGS`. Покрытие и версию правил возвращают в `NodeOutput.coverage` и `NodeOutput.rulesVersion`. `PARTIAL` может содержать находки.
- `WORKSPACE` передаётся как `java.nio.file.Path`, `PROJECT_MODEL` передаётся как объект внутри JVM. В API у этих портов только маркеры. Значения и PSI из модели не сериализуются.
- На каждом входном порту одна связь. Для нескольких веток у `logic.merge` восемь необязательных входов `findings1` … `findings8`. `logic.if` объявляет активную ветку наличием одного ключа в карте результата.
- Для экспорта C может зарегистрировать бин `workflow.engine.ReportExporter` с методами `json(report: JsonNode): JsonNode` и `markdown(report: JsonNode): String`.
- Для генерации D может зарегистрировать бин `workflow.engine.WorkflowGenerator` с методом `suspend fun generate(instructions: String): Workflow`. Сервер передаёт каталог и запрос, проверяет граф и делает одну повторную попытку после ошибок валидации.
- Проверенное объяснение D передаёт отдельным значением порта, реализующим `workflow.engine.ValidatedExplanation` со свойством `text: String`. Уведомления добавляют объяснение только из этого порта. Находки передаются независимо.
