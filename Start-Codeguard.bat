@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"

rem Запуск без Docker: нужен JDK 21 (сборка) и Node.js (сборка фронта) при первом запуске.
rem Необязательно: .env рядом со скриптом (см. .env.example), PORT (по умолчанию 8080).

set "JAVA_EXE="
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
if not defined JAVA_EXE (
  where java >nul 2>nul && set "JAVA_EXE=java"
)
if not defined JAVA_EXE (
  echo [ОШИБКА] Java не найдена. Установите JDK 21 ^(https://adoptium.net^) или задайте JAVA_HOME.
  goto :fail
)
"%JAVA_EXE%" -version 2>&1 | findstr /R /C:"version .21[.]" >nul
if errorlevel 1 (
  echo [ОШИБКА] Нужна Java 21. Найдена другая версия:
  "%JAVA_EXE%" -version
  echo Установите JDK 21 или укажите JAVA_HOME на него.
  goto :fail
)
if defined JAVA_HOME (set "JAVA_HOME=%JAVA_HOME:"=%")

set "JAR=backend\app\build\libs\codeguard-launch.jar"
if not exist "%JAR%" (
  echo Первый запуск: сборка приложения, это займёт несколько минут...
  where npm >nul 2>nul
  if errorlevel 1 (
    echo [ОШИБКА] Не найден Node.js/npm ^(нужен для сборки интерфейса^). Установите Node.js 20+.
    goto :fail
  )
  if not exist "frontend\dist\index.html" (
    pushd frontend
    call npm ci || (popd & echo [ОШИБКА] npm ci не удался & goto :fail)
    call npm run build || (popd & echo [ОШИБКА] сборка фронтенда не удалась & goto :fail)
    popd
  )
  call "%~dp0gradlew.bat" --no-daemon -PoneClickLaunch :backend:app:bootJar -x test
  if errorlevel 1 (echo [ОШИБКА] Gradle-сборка не удалась & goto :fail)
)
if not exist "%JAR%" (echo [ОШИБКА] не найден %JAR% & goto :fail)

rem Загрузка .env: строки KEY=VALUE, комментарии # пропускаются
if exist ".env" (
  for /f "usebackq eol=# tokens=1* delims==" %%A in (".env") do (
    if not "%%B"=="" set "%%A=%%B"
  )
)
if not defined PORT set "PORT=8080"

echo Запуск на http://127.0.0.1:%PORT% ^(остановка: Ctrl+C^)
if not defined NO_BROWSER start "" /b cmd /c "timeout /t 12 /nobreak >nul & start "" http://127.0.0.1:%PORT%"
"%JAVA_EXE%" -jar "%JAR%" --server.address=127.0.0.1 --server.port=%PORT%
goto :end

:fail
if not defined NO_PAUSE pause
exit /b 1
:end
endlocal
