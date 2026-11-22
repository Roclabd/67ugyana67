# syntax=docker/dockerfile:1
# Запуск одной командой: docker compose up --build  ->  http://127.0.0.1:8080

# 1. Фронтенд
FROM node:20-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# 2. Бэкенд со встроенным фронтом (processResources берёт frontend/dist)
FROM eclipse-temurin:21-jdk AS backend
WORKDIR /src
COPY gradlew settings.gradle.kts build.gradle.kts ./
COPY gradle gradle
RUN chmod +x gradlew
COPY backend backend
COPY fixtures fixtures
COPY ci-examples ci-examples
COPY --from=frontend /src/frontend/dist frontend/dist
RUN ./gradlew --no-daemon -PoneClickLaunch :backend:app:bootJar -x test \
    && cp backend/app/build/libs/codeguard-launch.jar /app.jar

# 3. Рантайм
FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /app app \
    && mkdir -p /app/data && chown -R app:app /app
WORKDIR /app
COPY --from=backend --chown=app:app /app.jar /app/app.jar
USER app
ENV APP_BIND_ADDRESS=0.0.0.0 \
    APP_DATA_DIR=/app/data \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70"
VOLUME /app/data
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/api/nodes -o /dev/null || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
