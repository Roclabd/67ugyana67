# analyzers/sast
Taint и правила SAST: sql-injection, tls-verification, credentialed-cors, route-authorization, object-authorization.

## Как устроено

- `project/` — разбор Kotlin PSI (kotlin-compiler-embeddable), карта строк (CRLF/CR/BOM не сдвигают строки).
- `index/` — индекс функций, классов, строковых констант; вычисление строковых значений.
- `spring/` — эндпоинты и источники параметров, цепочки `authorizeHttpRequests` по порядку, сопоставление путей, таблицы и owner-колонки.
- `taint/` — лёгкий taint: локальные присваивания, шаблоны, `+`, `format`, `buildString`, переход в функции проекта (до 3 уровней); нейтрализация приведением к числу/UUID.
- `rules/` — по классу на правило: `SqlInjectionRule`, `TlsVerificationRule`, `CredentialedCorsRule`, `RouteAuthorizationRule`, `ObjectAuthorizationRule`. Новое правило = новый класс + строка в `SastAnalyzer.DEFAULT_RULES`.
- Каждая находка несёт `evidence` (источник → вызовы → сток / правило). Безопасные проверенные места — в `coverage.dismissed`, неустановленное — в `coverage.unresolved`.

## Запуск

Из корня репозитория, JDK 21:

```bash
./gradlew :sast:test
./gradlew :sast:sast --args="fixtures/training/sample-project"
```

В платформе — нода `analyzer.sast` (`workflow/analyzers/sast/SastNode.kt`): вход — `ProjectModel` из «Разбор проекта» (адаптер `SastProjectAdapter`), выход — находки по `contracts/finding.schema.json`, покрытие и `rulesVersion`; параметры — классы проверок и порог критичности.

Тесты: учебный проект против эталона авторов набора (`TrainingProjectTest`) и вариации `src/test/resources/variants/*/expected.json` (`VariantsTest`).
