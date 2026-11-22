# frontend — React + TypeScript + React Flow

Ядро: каркас, `src/api/**`, `src/ui/**`, `src/store/**`, `src/editor/**`, `src/run/**`, `src/features/**`, `src/App.tsx`, `src/paths.ts`, `package.json`, конфиги, `scripts/**`.
Экраны: `src/screens/{report,history,templates,ci,settings}/**`, только через PR.

## Команды

```bash
npm ci
npm run dev:demo   # без бэка, данные из src/api/fixtures — http://localhost:5173
npm run dev         # с бэком: /api проксируется на http://localhost:8080
npm run typecheck
npm run lint
npm run build
```

## Как запустить e2e

Тесты Playwright работают с настоящим API и создают сценарий, загрузку ZIP и запись о запуске. Используйте отдельный локальный экземпляр приложения с тестовой базой.

Установите зависимости и браузер из каталога `frontend/`.

```bash
npm ci
npx playwright install --only-shell chromium
```

Когда сервер запущен на порту 8080, запустите `npm run dev` из `frontend/` и в другом терминале выполните `npm run e2e` из того же каталога. По умолчанию тесты открывают `http://127.0.0.1:5173`, а Vite проксирует запросы к API.

Для собранного JAR укажите его адрес в `E2E_BASE_URL`. Если на машине уже установлен Chrome или Edge, задайте `E2E_BROWSER_CHANNEL=chrome` или `E2E_BROWSER_CHANNEL=msedge`. С этими настройками установка Chromium через Playwright не требуется.

```bash
E2E_BASE_URL=http://127.0.0.1:8080 E2E_BROWSER_CHANNEL=chrome npm run e2e
```

В PowerShell:

```powershell
$env:E2E_BASE_URL = 'http://127.0.0.1:8080'
$env:E2E_BROWSER_CHANNEL = 'chrome'
npm run e2e
```

Тест на компьютере собирает граф в редакторе и проверяет пять находок с маской `****` в отчёте. В `e2e/fixtures/secrets.zip` лежат маркер Gradle-проекта `build.gradle.kts` и копия `secrets.properties` с пятью вымышленными значениями. Если меняете значения, обновите обе копии. Второй тест проверяет меню и параметры ZIP-этапа при ширине 390 пикселей.

При падении скриншот и `trace.zip` сохраняются в `test-results/e2e/`. Откройте трассу через `npx playwright show-trace <путь-к-trace.zip>`.

## Устройство

| Папка | Что там |
|---|---|
| `src/api/types.ts` | все типы ответов API — единственный источник типов (`docs/API.md`, `contracts/finding.schema.json`) |
| `src/api/client.ts` | `api.*` — все запросы; `subscribeRunEvents` — SSE запуска. `fetch` в остальных файлах запрещён ESLint |
| `src/api/useApi.ts` | `useApi` (загрузка: loading / error / ready) и `useAction` (кнопка-действие) |
| `src/api/mocks`, `src/api/fixtures` | мок-сервер в браузере с той же формой ответов; отчёты собраны из эталона авторов набора (`scripts/gen-report-fixture.mjs`) |
| `src/ui` | общие компоненты (`Page`, `AsyncView`, `CoverageBanner`, бейджи…), форматирование, стили |
| `src/store` | zustand: каталог нод, живое состояние текущего запуска |
| `src/editor` | редактор графа: палитра, холст, проверка типов портов, форма параметров по JSON-схеме |
| `src/run` | страница запуска, данные нод |
| `src/features/workflows` | список сценариев — **экран-образец** для экранов A |
| `src/screens/*` | экраны A (сейчас заглушки с подписанными пропсами) |

Правило: интерфейс ничего не разрешает сам. Сохранение, запуск, публикация, статус CI — решение сервера; экран показывает его ответ. Секреты приходят маской `••••`, отправка маски обратно = «не менять».

## Пакеты задач для A

