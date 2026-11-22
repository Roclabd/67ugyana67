# Публичное демо на VPS

Сервис открывается по домену (или QR-коду) без входа, поэтому включается демо-режим `APP_PUBLIC_DEMO=true`.
Обычный локальный запуск от этого файла не меняется.

## Что делает демо-режим

- Все изменяющие запросы к API отвечают `403 «Недоступно в демо-режиме»`: настройки LLM, репозиториев и Telegram,
  `/api/integrations/telegram/*`, создание, правка и удаление сценариев, импорт YAML, вебхуки и CI-запуски, решения по согласованию.
- Разрешено: открыть любой экран, скопировать шаблон (`POST /api/templates/{id}/copy`), загрузить ZIP до 25 МБ,
  запустить сценарий. Секреты в настройках всегда маскируются.
- Запуск идёт только на репозиториях из `APP_PUBLIC_DEMO_REPOS` (по умолчанию `https://github.com/example-org/training`).
  Ссылка, введённая посетителем, не подключается автоматически.
- Ноды `notify.*` и ожидание решения вырезаются из сценария перед запуском: из публичного сайта ничего не уходит в Telegram, почту и вебхуки.
  Расписание (cron) и команды Telegram-бота выключены.
- ИИ-объяснения: `APP_PUBLIC_DEMO_AI=true|false`, не больше `APP_PUBLIC_DEMO_AI_PER_HOUR` (20) запусков с ИИ в час на весь сервер;
  сверх лимита отчёт строится без объяснений. Ответы модели кэшируются.
- Лимиты: `APP_PUBLIC_DEMO_RUNS_PER_HOUR` (6) запусков в час с одного адреса, `APP_PUBLIC_DEMO_MAX_CONCURRENT` (2) одновременных запуска
  на весь сервер, загрузки ZIP вдвое чаще запусков. Сверх лимита `429` с понятным сообщением.
- Адрес клиента берётся из `X-Forwarded-For` только если запрос пришёл от `APP_TRUSTED_PROXY` (в compose это фиксированный адрес Caddy).
- `GET /api/meta` отвечает `{"publicDemo": true, ...}`, интерфейс показывает баннер и блокирует кнопки сохранения.

Без Docker (`java -jar`): `APP_PUBLIC_DEMO=true`, `APP_BIND_ADDRESS=0.0.0.0` и `APP_ALLOWED_HOSTS=<домен или IP>`. Без `APP_ALLOWED_HOSTS`
приложение в демо-режиме не стартует (Host-проверка иначе пустит только localhost).

## Требования к VPS

2 vCPU, 4 ГБ RAM, 20 ГБ диска, Ubuntu 22.04+ с Docker и плагином Compose. Открыты порты 80 и 443, DNS-запись домена указывает на сервер.

## Установка

```bash
git clone <репозиторий> && cd <репозиторий>
cp .env.example .env
```

В `.env` задайте:

```
DOMAIN=demo.example.com
APP_SECRETS_KEY=<32 байта в base64, например: openssl rand -base64 32>
# необязательно, для ИИ-объяснений:
LLM_BASE_URL=...
LLM_MODEL=...
LLM_API_KEY=...
# необязательно: другие разрешённые репозитории через запятую
APP_PUBLIC_DEMO_REPOS=https://github.com/example-org/training
```

Токены Telegram и SMTP в демо не нужны (уведомления отключены).

```bash
docker compose --env-file .env -f deploy/docker-compose.public.yml up -d --build
```

Caddy сам получит сертификат для `DOMAIN`. Приложение наружу не опубликовано, доступно только через прокси
(JVM `-Xmx1g`, лимит памяти контейнера 1,5 ГБ, `restart: unless-stopped`).

## Готовые отчёты для показа

```bash
deploy/seed-demo.sh            # адрес берётся из DOMAIN в .env, либо: deploy/seed-demo.sh https://demo.example.com
```

Скрипт архивирует учебный проект `fixtures/training/sample-project`, создаёт копию шаблона «Проверить ZIP-архив»
и запускает его `SEED_RUNS` раз (по умолчанию 2). Запуски идут с адреса сервера и учитываются в лимите 6 в час.

## Обслуживание

```bash
docker compose --env-file .env -f deploy/docker-compose.public.yml logs -f app
docker compose --env-file .env -f deploy/docker-compose.public.yml down        # данные сохраняются в томах
docker compose --env-file .env -f deploy/docker-compose.public.yml down -v     # со сбросом данных
```
