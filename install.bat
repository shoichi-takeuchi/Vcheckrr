@echo off
chcp 65001 > nul
echo ============================================================
echo  秀丸メール フィッシング検知システム - インストール
echo ============================================================
echo.

REM Pythonの確認
python --version > nul 2>&1
if errorlevel 1 (
    echo [エラー] Pythonがインストールされていません。
    echo https://www.python.org/ からPython 3.8以上をインストールしてください。
    pause
    exit /b 1
)

echo [OK] Python確認済み
python --version

echo.
echo 必要なパッケージをインストールします...
echo.

REM pipのアップグレード
python -m pip install --upgrade pip --quiet

REM 依存パッケージのインストール
python -m pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [警告] 一部のパッケージのインストールに失敗しました。
    echo 手動でインストールしてください: pip install -r requirements.txt
) else (
    echo.
    echo [OK] パッケージインストール完了
)

echo.
echo ============================================================
echo  インストール完了！
echo.
echo  次のステップ:
echo  1. config.json を開いて設定を確認してください
echo     - paths.mail_data_dir: メールデータのパス (D:\TuruKameData)
echo     - update.github_repo: GitHubリポジトリ名 (任意)
echo  2. start.bat をダブルクリックして起動してください
echo ============================================================
echo.
pause
