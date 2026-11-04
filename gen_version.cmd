@echo off
setlocal
set "OUT=%~1"
set "CNT=" & set "SHA=" & set "DIRTY="
git rev-list --count HEAD >"%TEMP%\capemon_cnt.txt" 2>nul
git rev-parse --short=8 HEAD >"%TEMP%\capemon_sha.txt" 2>nul
set /p CNT=<"%TEMP%\capemon_cnt.txt"
set /p SHA=<"%TEMP%\capemon_sha.txt"
git update-index -q --refresh >nul 2>&1
git diff-index --quiet HEAD -- || set "DIRTY=+"
set "VER=unknown"
if defined CNT if defined SHA set "VER=%CNT%-%SHA%%DIRTY%"
> "%OUT%.new" echo #define CAPEMON_GIT_VERSION "%VER%"
fc /b "%OUT%.new" "%OUT%" >nul 2>&1
if errorlevel 1 (move /y "%OUT%.new" "%OUT%" >nul) else (del "%OUT%.new")
exit /b 0