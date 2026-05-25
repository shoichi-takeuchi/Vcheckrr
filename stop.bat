@echo off
chcp 65001 > nul
echo フィッシング検知システムを停止します...

taskkill /f /im python.exe /fi "WINDOWTITLE eq *main.py*" > nul 2>&1
taskkill /f /fi "IMAGENAME eq python.exe" /fi "COMMANDLINE eq *08_Vcheck*" > nul 2>&1

REM より確実に停止するためにプロセスを検索
for /f "tokens=2" %%i in ('tasklist /fi "IMAGENAME eq python.exe" /fo table /nh 2^>nul') do (
    wmic process where "ProcessId=%%i" get CommandLine 2>nul | findstr /i "main.py" > nul
    if not errorlevel 1 (
        taskkill /f /pid %%i > nul 2>&1
        echo [OK] プロセス %%i を停止しました
    )
)

echo.
echo 停止完了。
echo ※Pythonが他でも動作している場合は、手動でタスクマネージャーから停止してください。
timeout /t 3 > nul
