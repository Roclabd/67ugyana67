# Разбор проекта

Нода «Разбор проекта» (`analyzer.parse`) получает `Path` через порт `workspace` типа `WORKSPACE` и отдаёт общую модель через порт `model` типа `PROJECT_MODEL`. Spring регистрирует ноду при подключении модуля `backend:analyzers`. Модель используется внутри процесса. Движок публикует только метку порта, а нода возвращает счётчики и ошибки разбора в покрытии. [Контракт модели](../../../contracts/project-model.md)

Модель индексирует Kotlin через PSI, конфигурацию YAML/properties/.env, явные зависимости Gradle, маршруты и правила Spring Security, а также структуру таблиц. Билд анализируемого проекта, миграции и пользовательский код не выполняются. Неоднозначные вызовы и вычисляемые значения могут остаться неразрешёнными. Для известных ошибок разбора возвращается `PARTIAL` с доступной частью модели. Если каталог снимка недоступен, нода возвращает `FAILED`.

Проверка из корня репозитория с JDK 21:

```powershell
.\gradlew.bat :backend:analyzers:test
```

## Каталог версий Spring Boot

Таблицы `src/main/resources/spring-boot-bom/*.tsv` содержат версии из опубликованных BOM `org.springframework.boot:spring-boot-dependencies` с учётом импортов Maven. При сканировании модель читает эти таблицы из ресурсов приложения локально.

| Релиз | Координат | Исходный BOM |
| --- | ---: | --- |
| 3.5.8 | 1472 | [Maven Central](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/3.5.8/spring-boot-dependencies-3.5.8.pom) |
| 4.0.9 | 1765 | [Maven Central](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/4.0.9/spring-boot-dependencies-4.0.9.pom) |

Для обновления каталога запустите команды из корня репозитория с Maven 3.9.11, JDK 21 и Python 3. Maven загружает зависимости для effective POM только из Maven Central, используя отдельный пустой кеш и строгую проверку контрольных сумм (`-C`). В `$bootVersions` перечислите релизы, которые нужно выгрузить. [Документация Maven Help Plugin](https://maven.apache.org/plugins-archives/maven-help-plugin-3.6.0/effective-pom-mojo.html)

```powershell
$target = (Resolve-Path 'backend/analyzers/model/src/main/resources/spring-boot-bom').Path
$temp = Join-Path ([IO.Path]::GetTempPath()) ('spring-boot-bom-' + [guid]::NewGuid())
$bootVersions = '3.5.8', '4.0.9'
New-Item -ItemType Directory -Path $temp | Out-Null
Push-Location $temp
try {
    @'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>bom.generator</groupId>
  <artifactId>generator</artifactId>
  <version>1</version>
</project>
'@ | Set-Content -Encoding ascii pom.xml
    @'
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <mirrors>
    <mirror>
      <id>central-only</id>
      <mirrorOf>*</mirrorOf>
      <url>https://repo.maven.apache.org/maven2</url>
    </mirror>
  </mirrors>
</settings>
'@ | Set-Content -Encoding ascii settings.xml
    foreach ($version in $bootVersions) {
        mvn -B -q -C -gs settings.xml -s settings.xml '-Dmaven.repo.local=./m2' `
            "-Dartifact=org.springframework.boot:spring-boot-dependencies:$version" `
            "-Doutput=effective-$version.xml" `
            org.apache.maven.plugins:maven-help-plugin:3.6.0:effective-pom
        if ($LASTEXITCODE -ne 0) { throw "Maven failed for Spring Boot $version" }
    }
    @'
from collections import defaultdict
from pathlib import Path
import re
import sys
from xml.etree import ElementTree

namespace = {"": "http://maven.apache.org/POM/4.0.0"}
target = Path(sys.argv[1])
for path in sorted(Path.cwd().glob("effective-*.xml")):
    project = ElementTree.parse(path).getroot()
    versions = defaultdict(set)
    for dependency in project.findall("dependencyManagement/dependencies/dependency", namespace):
        if dependency.findtext("type", "jar", namespace) != "jar":
            continue
        if dependency.findtext("classifier", "", namespace):
            continue
        group = dependency.findtext("groupId", "", namespace)
        artifact = dependency.findtext("artifactId", "", namespace)
        version = dependency.findtext("version", "", namespace)
        versions[f"{group}:{artifact}"].add(version)

    lines = []
    for coordinate, candidates in sorted(versions.items()):
        if len(candidates) != 1 or not re.fullmatch(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+", coordinate):
            continue
        version, = candidates
        if re.fullmatch(r"[0-9][A-Za-z0-9._-]*", version) and not version.lower().endswith("-snapshot"):
            lines.append(f"{coordinate}\t{version}\n")

    release = project.findtext("version", namespaces=namespace)
    (target / f"{release}.tsv").write_bytes("".join(lines).encode("utf-8"))
    print(f"{release}: {len(lines)}")
'@ | python - $target
    if ($LASTEXITCODE -ne 0) { throw 'TSV generation failed' }
} finally {
    Pop-Location
}
```

В TSV попадают только обычные JAR без классификатора с однозначной фиксированной версией. Строки отсортированы по `group:artifact`. Кодировка UTF-8, разделитель полей TAB, перевод строки LF.

Перед коммитом просмотрите изменения существующих таблиц и содержимое новых. Обновите список релизов, ссылки на BOM и число координат в таблице выше по итогам генерации.

```powershell
$catalog = 'backend/analyzers/model/src/main/resources/spring-boot-bom'
git diff HEAD -- $catalog
git ls-files --others --exclude-standard -- $catalog | ForEach-Object {
    git diff --no-index -- /dev/null $_
}
```
