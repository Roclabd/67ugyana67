# Контракт API фронт ↔ бэк

> ЧЕРНОВИК v0. Статусы: ✅ работает на живом бэке · ⏳ фронт работает на моках по описанной форме. Меняется только по договорённости B и D (C — для формы отчёта). По умолчанию тела запросов и ответов используют JSON UTF-8. Исключения указаны в таблицах.

Статусы обновлены после проверки HTTP-маршрутов на запущенном сервере.

## Запуск одним кликом

Нужны JDK 21 и Node.js 20 или новее с npm. В Windows запустите `scripts/start.bat`, в Linux и macOS выполните `./scripts/start.sh`. Скрипт собирает фронтенд и JAR, запускает их по одному локальному адресу и открывает браузер после старта сервера. Для работы из терминала без браузера добавьте `--no-browser`. Сервер слушает `127.0.0.1`, порт по умолчанию `8080`.

Для необязательных интеграций скопируйте `.env.example` в `.env` в корне проекта. Публичный учебный Git-репозиторий добавляется в список разрешённых через настройки, без перезапуска сервера.

## Каталог нод

| | Метод | Путь | Ответ |
|---|---|---|---|
| ✅ | GET | `/api/nodes` | `[{type, title, description?, category, inputs:[{name,type,required}], outputs:[...], paramsSchema, secretParams:[...]}]` |

В режиме живого API палитра, порты и форма параметров берутся из `GET /api/nodes`. Моки фронта используют собственные демонстрационные графы. При переносе такого графа в живой API сверяйте порты и параметры с каталогом.

| Нода | Живой каталог |
|---|---|
| `trigger.manual`, `trigger.cron`, `trigger.webhook` | Выход `trigger`. У cron параметры `cron` и `zone`. Входящий вебхук проверяет серверный `CI_TOKEN`. |
| `source.repo`, `source.archive` | Вход `trigger`, выходы `workspace` и `revision`. Настройки источника `url` или `uploadId`, а также необязательный относительный `subdir`. У Git-источника можно указать `branch` или полный `commitSha`. По умолчанию берётся удалённый `HEAD`, а при запуске из CI используется SHA события. Для учебного репозитория укажите `subdir: "sample-project"`. |
| `logic.merge` | Входы `findings1` … `findings8`, выход `findings`. Дедупликация отдельной нодой `logic.deduplicate`. |
| `logic.if` | Входы `decision` и необязательный `value`, выходы `true` / `false`. Решение строят `logic.compare` или `logic.regex`. |
| `logic.delay` | Задерживает передачу входа `value` в выход `value` на целое число секунд от 1 до 10. |
| `logic.filter-category` | Фильтрует `findings` по `category` (`SECRET`, `SAST` или `SCA`) и необязательному точному `class`. |
| `logic.only-new` | Сравнивает `findings` с базовой линией и возвращает `findings` и `details`. |
| `approval.wait` | Запрашивает решение для находки и передаёт его через `accepted`, `task` или `remediation`. |
| `proof.sandbox` | Нода модуля SAST. Её параметры и порты перечислены в `GET /api/nodes`. |
| `notify.telegram`, `notify.smtp`, `notify.webhook` | Telegram принимает `token` и `chatId`; SMTP — `to`, параметры подключения находятся в окружении; HTTPS-вебхук — `url` и необязательный Bearer `token`. |

`analyzer.parse`, `analyzer.secret`, `analyzer.sca`, `analyzer.sast` и `ai.explain` появляются в каталоге после регистрации соответствующих SPI-бинов. Автономный SAST включён в корневую сборку Gradle.

Telegram отправляет карточку со статусом, счётчиками по критичности, максимум тремя приоритетными находками и рекомендацией для первой, если она есть. Полный `report.md` прикладывается отдельным сообщением при наличии результата проверки. Telegram и SMTP показывают до пяти причин неполного анализа. При наличии номера строки причина отображается рядом с `файл:строка`. Задайте `APP_PUBLIC_URL` с доступным получателю базовым HTTP(S)-адресом интерфейса, чтобы появилась кнопка отчёта в Telegram и ссылка на запуск в SMTP.

## Сценарии

| | Метод | Путь | Тело / ответ |
|---|---|---|---|
| ✅ | GET | `/api/workflows` | `[{id, name, version, updatedAt}]` |
| ✅ | GET | `/api/workflows/{id}` | `Workflow` — `{id, name, version, nodes:[{id,type,params,position:{x,y},continueOnError?}], edges:[{id, from:{node,port}, to:{node,port}}]}`; секретные параметры приходят маской `"••••"` |
| ✅ | POST | `/api/workflows` | тело `Workflow` без `id` → `Workflow` или `422 {code,message,details:{errors:[GraphError]}}` |
| ✅ | PUT | `/api/workflows/{id}` | тело `Workflow`; маска `"••••"` в секретном параметре = «не менять» → новый `version` или `422` |
| ✅ | DELETE | `/api/workflows/{id}` | `204`, история остаётся доступна |
| ✅ | POST | `/api/workflows/validate` | тело `Workflow` → `{errors:[{nodeId?, edgeId?, code, message}]}` |
| ✅ | POST | `/api/workflows/generate` | `{text}` → `{workflow, errors:[]}`. API возвращает `503`, если модель не настроена или не ответила вовремя, и `502`, если LLM не вернула корректный сценарий. |
| ✅ | GET | `/api/workflows/{id}/export.yaml` | YAML сценария без значений секретных параметров |
| ✅ | POST | `/api/workflows/import.yaml` | тело YAML → новый сценарий после GraphValidator |

Для `POST /api/workflows/{id}/baseline`, `POST /api/workflows/{id}/risks` и `POST /api/approvals/{id}/decision` используйте Bearer-токен из `APP_REVIEW_TOKEN`. Базовая линия получает `{runId}`, принятие риска — `{runId, fingerprint, reason}`, решение — `{choice, reason?}`. Значения `choice` — `ACCEPT_RISK`, `CREATE_TASK`, `VIEW_REMEDIATION`. Для принятия риска причина обязательна.

`logic.only-new` сравнивает все находки после слияния. Базовая линия применяется в той же версии сценария, области источника и версии правил. Для Git сравниваются коммиты одного репозитория и подпапки. Для ZIP область привязана к хэшу архива. Узел возвращает находки и `details` со статусом сравнения и исчезнувшими отпечатками при полном покрытии.

`approval.wait` выдаёт решение в выбранный выход `accepted`, `task` или `remediation`. Идентификатор запроса появляется в журнале ноды. `timeoutSeconds` задаёт время ожидания от 1 до 300 секунд, по умолчанию 180. Суммарный бюджет ожидания в одном запуске ограничен 600 секундами. Принятый риск сохраняется после завершения запуска с полным покрытием. Для кнопок Telegram настройте входящий webhook `POST /api/telegram/approvals` с `TELEGRAM_APPROVAL_WEBHOOK_SECRET` и разрешённым отправителем `TELEGRAM_APPROVER_USER_ID` (либо владельцем личного тестового чата).

## Запуски

| | Метод | Путь | Тело / ответ |
|---|---|---|---|
| ✅ | POST | `/api/workflows/{id}/run` | `{source?: {kind:"upload", uploadId} \| {kind:"repo", url}}` → `{runId}` |
| ✅ | GET | `/api/runs/{runId}/events` | SSE: `node.status {nodeId, status, startedAt?, finishedAt?, error?}`, `node.io {nodeId, input, output}` (секреты замаскированы), `run.status {status}`, `log {nodeId, message}` |
| ✅ | GET | `/api/runs?workflowId=` | `RunSummary[]` |
| ✅ | GET | `/api/runs/{runId}` | `RunSummary` + `workflowVersion`, `nodeRuns[]`, `report` (объект или `null`) |
| ✅ | GET | `/api/runs/{runId}/report.json` | JSON авторов набора (`contracts/report-format.md`) |
| ✅ | GET | `/api/runs/{runId}/report.md` | Отчёт Markdown. |
| ✅ | GET | `/api/runs/{runId}/report.sarif` | SARIF 2.1.0 для GitHub Code Scanning. MIME-тип `application/sarif+json`, имя файла `report.sarif`. Если отчёта нет, API возвращает `404`. |
| ✅ | GET | `/api/runs/{runId}/sbom.cdx.json` | SBOM CycloneDX 1.5 (`application/vnd.cyclonedx+json`): `components[]` (type `library`, group, name, version, purl `pkg:maven/group/name@version`) и `vulnerabilities[]` (id, source, ratings, affects по purl). В SBOM попадают зависимости, найденные SCA в справочнике: уязвимые и проверенные чистые; зависимости без записей в справочнике анализатор не перечисляет (это записано в `metadata.properties`). |
| ✅ | GET | `/api/runs/{runId}/findings/{findingId}/patch` | Готовый патч находки: unified diff (`text/x-diff`, имя `fix-<id>.patch`) для `git apply` в папке проверенного проекта; пути относительны её корню. `findingId` - `id` или `fingerprint` находки. **SCA**: версия заменяется на первую безопасную по справочнику (вне всех уязвимых диапазонов) в строке, где версия записана литералом (`build.gradle.kts`, `gradle.properties`, `libs.versions.toml`, `extra[...]`). **SECRET**: литерал заменяется на `System.getenv("NAME") ?: error(...)` (Kotlin), `System.getenv("NAME")` (Java) или `${NAME}` (`.properties`, `.yml`), `NAME` берётся из имени поля в UPPER_SNAKE. **SAST**: `404` «Автоисправление для этого класса не поддерживается, см. рекомендацию». Прочие коды: `404` - нет запуска или находки, `409` - место правки ненадёжно (версия вычисляется, берётся из Spring Boot BOM, несколько вхождений; секрет в неподдерживаемом файле или на нескольких строках), `410` - снимок проекта запуска больше недоступен (патчи строятся при завершении запуска и хранятся в `<data>/patches/<runId>.json`; запуски до этой функции патчей не имеют). Ответ всегда с `Cache-Control: no-store`. |
| ✅ | GET | `/api/runs/{runId}/findings/{findingId}/patch?masked=true` | То же без значения секрета (в удаляемой строке `****`), только для показа на экране: к применению не годится. Без `masked` патч секрета содержит исходную строку (иначе `git apply` не сработает), поэтому отдаётся только запросам с локального адреса, остальным - `403`. Не публикуйте скачанный файл. |
| ✅ | POST | `/api/uploads` | multipart `file`, ZIP до 25 МБ → `{uploadId}` (zip slip) |

`RunSummary` содержит `{runId, workflowId, workflowName?, status, coverageStatus, counts, trigger?, repoUrl?, error?, startedAt, finishedAt}`. `workflowName` — название на момент запуска, `trigger` — строка `manual`, `cron` или `webhook`. `repoUrl` содержит URL Git-источника из снимка запуска или явно переданного источника. Если URL отсутствует или запуск обработал несколько разных Git-URL, поля нет. Во время выполнения `coverageStatus` и `finishedAt` равны `null`. `counts` всегда содержит `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` и отражает только известные находки. Полноту анализа показывает `coverageStatus`.

`RunSummary.delivery` (`{status, delivered[], failed[{nodeId, type, error}]}`) показывает исход доставки уведомлений (`notify.*`) отдельно от анализа. `status`: `NONE` (уведомлений не было), `DELIVERED`, `PARTIAL`, `FAILED`. Сбой доставки (не настроен Telegram, не дошёл файл, отказ вебхука) не меняет `status` запуска и `coverageStatus`: они считаются только по источнику и анализаторам. Если все анализаторы завершились полностью, запуск остаётся `SUCCESS`/`COMPLETE`, отчёт сохраняется и доступен в истории, API и экспортах. CI-гейт не смотрит на `delivery`. Причины в `failed[].error` замаскированы. Для запуска с ошибкой источника или анализа (`FAILED`) `delivery` описывает отправку уведомления о сбое.

Прямые ссылки интерфейса (`/settings`, `/projects`, `/templates`, `/runs/{id}/report`) в собранном JAR отдают `index.html`, если браузер просит `text/html`. Пути под `/api`, файлы с расширением и не-HTML запросы возвращают настоящий 404.

В отчёте `inputHash` привязан к фактически загруженному коммиту Git или SHA-256 загруженного ZIP. `coverage.byAnalyzer` содержит ноды, выдающие результаты проверки. Состояние разбора проекта учитывается в общем покрытии и в истории нод.

Проверка качества кода (`analyzer.quality`, шаблон `code-quality`) не относится к проверкам безопасности. Нода имеет категорию `OUTPUT` и выход `quality` типа `ANY`, всегда завершается `SUCCESS`; находки, покрытие, `counts`, SARIF, выгрузка авторов набора и CI-гейт её не учитывают. Если нода есть в сценарии, отчёт получает необязательный блок `quality`: `{version:1, status: OK|ISSUES|PARTIAL|TIMEOUT|NOT_APPLICABLE|ERROR, message, durationMs, filesAnalyzed, filesByLanguage, truncated, summary:{total, byKind}, diagnostics:[{kind: syntax|type-mismatch|unresolved-reference|functional-defect, rule, language, path, line, column, message, confidence: PROVEN|LIKELY}], skipped[], unsupported[], rules[]}`. В отчётах без ноды блока нет. Новый язык подключается бином `workflow.quality.LanguageChecker`.

SSE поддерживает повтор с `Last-Event-ID`. Дополнительное событие `node.progress {nodeId, percent, note?}`. У ноды есть необязательный `continueOnError` (по умолчанию `false`).

Статусы ноды: `PENDING | RUNNING | SUCCESS | PARTIAL | FAILED | SKIPPED`. Статус запуска: `RUNNING | SUCCESS | PARTIAL | FAILED`.

## CI

| | Метод | Путь | Тело / ответ |
|---|---|---|---|
| ⏳ | POST | `/api/ci/workflows/{id}/run?wait=true` | заголовок `Authorization: Bearer <ci-token>`, `{repoUrl, commitSha, branch}` → `{runId, status, coverageStatus, counts, pass: boolean, reason}`; `pass=false` при critical **или** `PARTIAL`/`FAILED`, **или** если в отчёте нет завершённых нод SECRET, SCA и SAST (`reason: MISSING_ANALYZERS`, список в `missingAnalyzers`) |
| ✅ | GET | `/api/ci/workflows/{id}/config?kind=github\|gitlab` | текст YAML |

Встроенный GitHub webhook `POST /api/webhooks/{id}` принимает `push` и `pull_request`, подписанные HMAC SHA-256 с секретом `CI_TOKEN`. Пайплайн вызывает REST с Bearer-токеном. Для успешного результата сервер сверяет снимок с SHA и сравнивает версию правил с `CI_RULES_VERSION`.

Пример GitHub Actions загружает SARIF для завершённого анализа с подтверждённым SHA при `PASS` и `CRITICAL_FINDINGS`. Критические находки по-прежнему блокируют проверку. Для просмотра отчёта на вкладке Security включите GitHub Code Scanning в репозитории. [Документация GitHub](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

## Шаблоны

| | Метод | Путь | Тело / ответ |
|---|---|---|---|
| ✅ | GET | `/api/templates` | `TemplateSummary[]`, где `TemplateSummary` — `{id, name, description, tags, nodeCount, author}` |
| ✅ | GET | `/api/templates/{id}` | `TemplateSummary` + `workflow` |
| ✅ | POST | `/api/templates` | `{workflowId, name, description}` → шаблон или `422` (граф не прошёл валидацию) |
| ✅ | POST | `/api/templates/{id}/copy` | Необязательное тело `{name?,repoUrl?,recipient?,uploadId?}` → новый `Workflow` |

## Настройки

| | Метод | Путь | Тело / ответ |
|---|---|---|---|
| ✅ | GET | `/api/settings/llm` | `{provider, baseUrl, model, apiKeySet: boolean}` |
| ✅ | PUT | `/api/settings/llm` | `{provider, baseUrl, model, apiKey?}` → та же форма ответа, что у GET. |
| ✅ | GET | `/api/settings/repositories` | `{repositories: string[]}` |
| ✅ | POST | `/api/settings/repositories` | `{url}` добавляет адрес и возвращает текущий список. Повторный адрес не создаёт дубль. |
| ✅ | PUT | `/api/settings/repositories` | `{repositories: string[]}` заменяет весь список. Пустой массив очищает список. |

LLM поддерживает `openai-compatible`, `groq`, `openrouter`, `ollama` и `vllm`. Адрес провайдера использует HTTPS. Для локального адреса разрешён HTTP на loopback. Ключ в ответах API не возвращается, `apiKeySet` показывает факт настройки. При смене сервера старый ключ не переносится. Настройки действуют до перезапуска и применяются сразу, в том числе к генерации сценария.

Список подключённых Git-репозиториев хранится в H2. До первого изменения используется `ALLOWED_REPOS`. Допускается до 100 корневых HTTPS-адресов репозиториев GitHub, GitLab и Bitbucket без параметров или учётных данных. Для одновременного добавления адресов используйте POST.

**Ссылка пользователя сама является разрешением.** Репозиторий подключается автоматически (ссылка нормализуется: без `/tree/…`, `.git` и завершающего `/`; повтор не создаёт дубль) при явном действии: `POST /api/templates/{id}/copy` с `repoUrl`, `POST`/`PUT /api/workflows` и `POST /api/workflows/import.yaml` с параметром `url` ноды `source.repo`, `POST /api/workflows/{id}/run` с `source: {kind: "repo", url}`, `POST /api/settings/repositories`. Ссылка не https или с неизвестным хостом отклоняется с кодом 422 и текстом «Поддерживаются ссылки на GitHub, GitLab и Bitbucket по https». Защита при клонировании не меняется: только https, публичный IP, закрепление DNS, без редиректов. Автоматические запуски (`POST /api/webhooks/{id}`, `POST /api/ci/workflows/{id}/run`, расписание) ничего не подключают и принимают только уже подключённые репозитории (они подключены, когда пользователь создал сценарий или проект с этой ссылкой).

## Команды Telegram-бота

Выключены по умолчанию. Включаются `TELEGRAM_BOT_COMMANDS=true` и требуют токен бота (настройки Telegram или `TELEGRAM_BOT_TOKEN`). Бот опрашивает `getUpdates` (long polling, 25 с, последний `offset` хранится в `data/telegram-bot-offset`) в одном фоновом потоке; при сетевых ошибках пауза растёт от 1 до 30 с, при ответе 409 (у бота задан webhook) опрос останавливается с одной записью в журнале. Исходящие запросы идут тем же путём, что и уведомления: только api.telegram.org, проверка DNS, `APP_OUTBOUND_PROXY`. Отвечает только чатам из настроек Telegram (`chatId` или `TELEGRAM_CHAT_ID`), остальные игнорируются без ответа. Секреты в ответах маскируются, сообщение не длиннее 4096 символов. Принимается и форма `/команда@ИмяБота`.

| Команда | Действие |
|---|---|
| `/help` | Список команд. |
| `/status` | Версия правил, число сценариев и подключённых репозиториев, последний запуск (статус, покрытие, счётчики по критичности, время), время сервера. |
| `/last` | Карточка последнего завершённого запуска (как в уведомлении, с кнопками при `APP_PUBLIC_URL`) и PDF-отчёт (запасной вариант Markdown). |
| `/run <ссылка>` | Запуск проверки (секреты, зависимости, код, AI-пояснение) по уже подключённому репозиторию; сам репозиторий из Telegram не подключается. Ответ «Запущено: id», по завершении в тот же чат приходят карточка и PDF. Не более одного одновременного запуска и 5 в час на чат; при занятых слотах бот сообщает об этом. Запуск идёт по служебному сценарию «Telegram: проверка репозитория по ссылке» (шаблон `release` без нод уведомлений). |
| `/runs` | Пять последних запусков одной строкой. |

## Работа через прокси/VPN

Если VPN подменяет DNS (адреса `198.18.0.0/15` для github.com, api.telegram.org), задайте в `.env` `APP_OUTBOUND_PROXY=http://127.0.0.1:10809` и перезапустите сервер. В журнале появится «Исходящие запросы через прокси host:port». Через прокси идут: `source.repo` (git `http.proxy`), Telegram и webhook (`PublicNetwork`), внешняя LLM. Имя хоста разрешает прокси, поэтому локальное разрешение и закрепление IP отключаются; остаются HTTPS, список `ALLOWED_REPOS`, запрет `localhost`, `*.local`, `*.internal` и приватных IP-адресов в URL, без редиректов и повторов. Локальная LLM (localhost, 127.0.0.1) идёт напрямую. SMTP через прокси не проксируется. Пустое значение возвращает прямые запросы с прежними проверками.

## Ошибки

`4xx/5xx` → `{code, message, details?}`. Для ошибки графа `422 INVALID_GRAPH` список `GraphError[]` находится в `details.errors`; верхнеуровневое `errors` сохранено для прежних клиентов. Фронт показывает `message` и использует `nodeId` / `edgeId` для подсветки.
