# Учебные вариации SECRET и SCA

Генератор создаёт воспроизводимые наборы для статической проверки. В каждом наборе есть `project/` и `truth.json` с находками, безопасными контролями и ожидаемым статусом покрытия. Все секреты в вариациях синтетические. Учебный набор авторов набора служит источником справочника. Файлы вариаций игнорируются Git.

Для генерации с Python 3.10 или новее:

```powershell
python -B tools/mutator/generate.py
```

Параметр `--output` задаёт другой каталог. Повторный запуск с теми же входами даёт те же файлы. При конфликте с существующим файлом генератор завершает работу с ошибкой.

Для сквозной проверки соберите приложение (`:backend:app:bootJar`) и запустите:

```powershell
python -X utf8 -B tools/mutator/check.py --jar backend/app/build/libs/app-0.1.0-SNAPSHOT.jar
```

Команда запускает приложение локально на временном порту, отправляет только сгенерированные снапшоты, сверяет JSON через evaluator и печатает таблицу в Markdown. При расхождении с эталоном или ожидаемым покрытием код выхода равен 1. При ошибке самого прогона код выхода равен 2. Для выбора установленной Java 21 можно передать `--java`.

Обе команды принимают `--variant <имя>` для запуска одного набора. Например, команда ниже сверяет предупреждение в разделе «Обратите внимание» для `src/test/.env` и проверяет, что тестовый секрет отсутствует среди находок.

```powershell
python -X utf8 -B tools/mutator/check.py --jar backend/app/build/libs/app-0.1.0-SNAPSHOT.jar --variant c7-secret-test-env
```

| Вариация | Что проверяет |
| --- | --- |
| `c7-secret-properties` | Литерал в файле `.properties` |
| `c7-secret-gradle-properties` | Литерал в `gradle.properties` |
| `c7-secret-compose` | Секреты в словаре и списке `environment` в `docker-compose.yml` |
| `c7-secret-catalog` | Литерал и обычная версия в `gradle/libs.versions.toml` |
| `c7-secret-kotlin-object` | Константа внутри Kotlin `object` |
| `c7-secret-kotlin-companion` | Константа внутри `companion object` |
| `c7-secret-kotlin-value` | Литеральное значение по умолчанию в Spring `@Value` |
| `c7-secret-test-env` | Предупреждение для литерала в `src/test/.env` |
| `c7-sca-gradle-extra` | Версия из прямого обращения к `extra[]` |
| `c7-sca-gradle-catalog` | Связка каталога версий с `strictly` и `version.ref` |
| `c7-sca-gradle-val` | Версия через Kotlin `val` |
| `c7-sca-gradle-properties` | Версия из `gradle.properties` через `by project` |
| `c7-secret-credential-url` | JDBC URL с литеральным паролем. URL без пароля и ссылка на переменную окружения служат контролями |
| `c7-secret-pem` | Синтетический блок PEM с маркером приватного ключа и контроль с публичным ключом |
| `c7-secret-base64` | Base64 в именованном секрете Kotlin и контроль с обычной меткой |
| `c7-secret-xml` | Литералы в logback.xml и pom.xml с контролями-подстановками |
| `c7-sca-named-coordinates` | Именованные group, name и version |
| `c7-sca-configurations` | Конфигурации api, kapt и runtimeOnly |
| `c7-sca-buildsrc` | Литеральная строковая константа объекта buildSrc с явным импортом |
| `c7-sca-convention` | Литеральная версия в convention-скрипте Kotlin DSL |
| `c7-sca-platform-lock` | Платформа Jackson BOM и версия, зафиксированная в gradle.lockfile |

Сквозной прогон проверяет все вариации через собранный JAR. Для платформы эталоном служит lockfile. Произвольные Gradle-плагины и удалённые BOM во время статического анализа не выполняются и не загружаются.
