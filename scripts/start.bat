@echo off
setlocal
where node.exe >nul 2>&1
if errorlevel 1 (
    echo Install Node.js 20 or newer with npm, then run this script again.
    pause
    exit /b 1
)
node "%~dp0start.mjs" %*
set "result=%errorlevel%"
if not "%result%"=="0" if not "%result%"=="130" if "%~1"=="" pause
exit /b %result%
