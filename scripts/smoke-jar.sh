#!/usr/bin/env bash
# Смоук собранного JAR: прямые HTML-ссылки интерфейса, API и настоящие 404.
# Использование: scripts/smoke-jar.sh <путь-к-jar> [порт]
# Предварительно: (cd frontend && npm ci && npm run build) и ./gradlew :backend:app:bootJar
set -u
jar="${1:?Укажите путь к JAR}"
port="${2:-8191}"
java_bin="${JAVA:-java}"
base="http://127.0.0.1:$port"
work="$(mktemp -d)"
log="$work/server.log"
failed=0

cleanup() { [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

# Рабочий каталог временный: своя база H2 и данные, .env репозитория не читается.
(cd "$work" && exec "$java_bin" -jar "$jar" --server.address=127.0.0.1 --server.port="$port" >"$log" 2>&1) &
pid=$!

for _ in $(seq 1 90); do
  curl -fs -o /dev/null "$base/api/nodes" && break
  kill -0 "$pid" 2>/dev/null || { echo "FAIL: сервер завершился при старте"; tail -30 "$log"; exit 1; }
  sleep 1
done

check() { # описание, ожидаемый код, ожидаемый фрагмент тела (необязательно), аргументы curl...
  local name="$1" want="$2" needle="$3"; shift 3
  local code body
  body="$(curl -s -o "$work/body" -w '%{http_code}' "$@")"; code="$body"
  if [ "$code" != "$want" ]; then
    echo "FAIL: $name: ждали HTTP $want, получили $code"; failed=1; return
  fi
  if [ -n "$needle" ] && ! grep -q "$needle" "$work/body"; then
    echo "FAIL: $name: в ответе нет '$needle'"; failed=1; return
  fi
  echo "ok: $name"
}

html=(-H "Accept: text/html")
check "GET /"                         200 'id="root"' "${html[@]}" "$base/"
check "GET /settings (прямая ссылка)" 200 'id="root"' "${html[@]}" "$base/settings"
check "GET /projects"                 200 'id="root"' "${html[@]}" "$base/projects"
check "GET /templates"                200 'id="root"' "${html[@]}" "$base/templates"
check "GET /runs/x/report (ссылка из Telegram)" 200 'id="root"' "${html[@]}" "$base/runs/x/report"
check "GET /api/nodes"                200 'analyzer' "$base/api/nodes"
check "GET /api/nope (настоящий 404)" 404 '' "${html[@]}" "$base/api/nope"
check "GET /assets/missing.js"        404 '' "${html[@]}" "$base/assets/missing.js"

[ "$failed" = 0 ] && echo "Смоук JAR пройден." || { echo "Смоук JAR не пройден. Лог сервера:"; tail -30 "$log"; exit 1; }
