#!/usr/bin/env bash
# Готовит демо: загружает учебный проект (fixtures/training/sample-project) ZIP-архивом и запускает
# шаблон «Проверить ZIP-архив», чтобы на сайте сразу были готовые отчёты.
# Запуск из корня репозитория:  deploy/seed-demo.sh [https://ваш-домен]   (по умолчанию https://$DOMAIN из .env)
set -euo pipefail

cd "$(dirname "$0")/.."
if [ -z "${1:-}" ] && [ -z "${DOMAIN:-}" ] && [ -f .env ]; then DOMAIN="$(grep -E '^DOMAIN=' .env | head -1 | cut -d= -f2-)"; fi
BASE="${1:-${BASE_URL:-https://${DOMAIN:?Укажите адрес: deploy/seed-demo.sh https://ваш-домен}}}"
BASE="${BASE%/}"
RUNS="${SEED_RUNS:-2}"
SRC=fixtures/training/sample-project
[ -d "$SRC" ] || { echo "Нет $SRC" >&2; exit 1; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
if command -v zip >/dev/null; then
  (cd "$SRC" && zip -qr "$tmp/demo.zip" . -x 'build/*' '.gradle/*')
else
  python3 - "$SRC" "$tmp/demo.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in ("build", ".gradle")]
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, src))
PY
fi

field() { grep -o "\"$1\" *: *\"[^\"]*\"" | head -1 | sed 's/.*: *"\(.*\)"/\1/'; }
J=(-H 'Content-Type: application/json')

echo "Копия шаблона zip-scan..."
workflow="$(curl -fsS "${J[@]}" -X POST -d '{}' "$BASE/api/templates/zip-scan/copy" | field id)"
[ -n "$workflow" ] || { echo "Не удалось создать сценарий" >&2; exit 1; }

for i in $(seq 1 "$RUNS"); do
  upload="$(curl -fsS -F "file=@$tmp/demo.zip;type=application/zip" "$BASE/api/uploads" | field uploadId)"
  run="$(curl -fsS "${J[@]}" -X POST -d "{\"source\":{\"kind\":\"upload\",\"uploadId\":\"$upload\"}}" "$BASE/api/workflows/$workflow/run" | field runId)"
  echo "Запуск $i: $run"
  status=""
  for _ in $(seq 1 90); do
    status="$(curl -fsS "$BASE/api/runs/$run" | tr -d '\n' | sed -n 's/^[^}]*"status" *: *"\([A-Z_]*\)".*/\1/p' | head -1 || true)"
    case "$status" in ""|RUNNING) sleep 4 ;; *) break ;; esac
  done
  echo "  статус: ${status:-неизвестен}"
done
echo "Готово: $BASE/history"
