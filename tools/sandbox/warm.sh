#!/usr/bin/env bash
# Сборка образа песочницы и прогрев кэша Gradle (один раз, с сетью): основной и тестовый classpath.
# Пустой тест кладётся в отдельный каталог — иначе зависимости тестов не скачиваются (у проекта может не быть своих тестов).
# Потом тесты-доказательства идут с --network none и --offline.
# Запуск из корня репозитория: bash tools/sandbox/warm.sh [путь к проекту, по умолчанию учебный]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
project="$(cd "${1:-fixtures/training/sample-project}" && pwd -W 2>/dev/null || pwd)"
docker build -t codeguard-sandbox "$here"
docker run --rm --cpus 2 --memory 3g --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,exec,size=2g -v "$project:/src:ro" -v codeguard-sandbox-gradle:/home/sandbox/.gradle \
  codeguard-sandbox sh -c 'cp -r /src/. /tmp/w && cd /tmp/w && chmod +x gradlew && mkdir -p /tmp/warm/proof &&
    printf "package proof\nclass Warm { @org.junit.jupiter.api.Test fun ok() {} }\n" > /tmp/warm/proof/Warm.kt &&
    ./gradlew --no-daemon -q test -PorganizerTests=/tmp/warm --tests proof.Warm'
echo "Песочница готова: образ codeguard-sandbox, кэш Gradle в томе codeguard-sandbox-gradle"
