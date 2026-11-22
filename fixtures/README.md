# Тестовые данные **Только для чтения**: ничего внутри `training/` не правим — это копия учебного набора авторов набора.

| Путь | Что |
|---|---|
| `training/` | копия https://github.com/example-org/training, коммит в `training/.source-commit` |
| `training/sample-project/` | проект Service Desk (Kotlin + Spring Boot + Gradle KTS) — корень проверки для анализаторов |
| `training/ground-truth/training-findings.json` | эталон: 15 находок + 6 контрольных примеров (`controls`) |
| `training/ground-truth/training-findings.md` | эталон таблицей — образец читаемого отчёта |
| `training/vulnerability-database/vulnerabilities.json` | справочник уязвимостей для SCA (41 запись, GitHub Advisory Database, CC BY 4.0) |
| `training/docs/submission-format.md` | формат JSON-отчёта, который мы обязаны выдавать |

Вариации для проверки устойчивости (мутатор C) складываем в `fixtures/variants/<имя>/` — генерируются `tools/mutator`, в git не коммитим (см. `.gitignore`), кроме 2–3 эталонных вариаций, нужных для тестов.

Сканировать можно только этот набор и наши учебные проекты (правило случая).
