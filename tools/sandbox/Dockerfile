# Песочница для тестов-доказательств (D5): чужой код собирается и тестируется только здесь.
# Запуск: без сети (--network none), без root, лимиты CPU/памяти/процессов, проект смонтирован только для чтения.
FROM eclipse-temurin:21-jdk
RUN useradd --create-home --uid 10001 sandbox \
    && mkdir -p /home/sandbox/.gradle \
    && chown -R sandbox:sandbox /home/sandbox
USER sandbox
ENV GRADLE_USER_HOME=/home/sandbox/.gradle
WORKDIR /home/sandbox
