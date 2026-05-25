@echo off
chcp 65001 > nul
echo ============================================================
echo  Windows スタートアップ登録
echo  PC起動時に自動的にフィッシング検知を開始します
echo ============================================================
echo.

REM スタートアップフォルダのパスを取得
set STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
set SCRIPT_DIR=%~dp0
set VBS_FILE=%SCRIPT_DIR%start_hidden.vbs
set SHORTCUT_FILE=%STARTUP_DIR%\HidemarPhishingDetector.lnk

echo スタートアップフォルダ: %STARTUP_DIR%
echo VBSファイル: %VBS_FILE%
echo.

REM ショートカット作成
powershell -Command ^
  "$ws = New-Object -ComObject WScript.Shell; ^
   $sc = $ws.CreateShortcut('%SHORTCUT_FILE%'); ^
   $sc.TargetPath = 'wscript.exe'; ^
   $sc.Arguments = '\"%VBS_FILE%\"'; ^
   $sc.WorkingDirectory = '%SCRIPT_DIR%'; ^
   $sc.Description = '秀丸メール フィッシング検知システム'; ^
   $sc.Save()"

if exist "%SHORTCUT_FILE%" (
    echo [OK] スタートアップに登録しました。
    echo 次回PC起動時から自動的に監視が開始されます。
) else (
    echo [エラー] ショートカットの作成に失敗しました。
    echo 手動で "%VBS_FILE%" のショートカットを
    echo "%STARTUP_DIR%" に作成してください。
)

echo.
pause
