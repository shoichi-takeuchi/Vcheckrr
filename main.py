"""
main.py - 秀丸メール フィッシング検知システム エントリーポイント
常駐プロセスとして起動し、メールフォルダを監視する
"""
import os
import sys
import json
import time
import signal
import logging
import argparse
import threading
from datetime import datetime

# 起動ディレクトリをPATHに追加
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from monitor import MailMonitor
from updater import AutoUpdater
from notifier import notify_startup, notify_update

# ========== 設定 ==========
APP_NAME = "秀丸メール フィッシング検知"
APP_VERSION = "1.0.0"
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
LOG_FILE = os.path.join(BASE_DIR, 'logs', 'system.log')


def setup_logging(log_level: str = 'INFO'):
    """ロギングを設定する"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    # ログフォーマット
    fmt = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'

    # [改善] RotatingFileHandler でログローテーション（最大5MB × 5世代）
    from logging.handlers import RotatingFileHandler
    rotating_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=5,
        encoding='utf-8'
    )
    rotating_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root_logger.addHandler(rotating_handler)
    root_logger.addHandler(console_handler)

    # 外部ライブラリのログを抑制
    for noisy in ('watchdog', 'urllib3', 'urllib'):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def load_config() -> dict:
    """設定ファイルを読み込む"""
    if not os.path.exists(CONFIG_FILE):
        print(f"エラー: 設定ファイルが見つかりません: {CONFIG_FILE}")
        sys.exit(1)

    with open(CONFIG_FILE, encoding='utf-8') as f:
        return json.load(f)


def run_update_loop(updater: AutoUpdater, monitor: MailMonitor, interval_hours: float):
    """バックグラウンドで定期更新チェックを実行する"""
    logger = logging.getLogger('updater_loop')
    while True:
        time.sleep(interval_hours * 3600)
        try:
            logger.info("定期更新チェック開始")
            updated, files = updater.check_and_update_rules()
            if updated:
                monitor.reload_rules()
                notify_update(APP_NAME, files)
                logger.info(f"ルール更新完了: {files}")
        except Exception as e:
            logger.error(f"定期更新エラー: {e}")


def main():
    """メイン処理"""
    parser = argparse.ArgumentParser(
        description=f'{APP_NAME} v{APP_VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  python main.py              # 通常起動（常駐監視）
  python main.py --debug      # デバッグモードで起動
  python main.py --update     # 強制更新後に起動
  python main.py --scan-only  # 一度だけスキャンして終了
  python main.py --status     # 設定状態を表示して終了
        """
    )
    parser.add_argument('--debug', action='store_true', help='デバッグモードで起動')
    parser.add_argument('--update', action='store_true', help='起動前に強制更新')
    parser.add_argument('--scan-only', action='store_true', help='一度スキャンして終了')
    parser.add_argument('--status', action='store_true', help='状態を表示して終了')
    parser.add_argument('--no-update', action='store_true', help='自動更新を無効化して起動')
    args = parser.parse_args()

    # ログ設定
    log_level = 'DEBUG' if args.debug else 'INFO'
    setup_logging(log_level)
    logger = logging.getLogger('main')

    print(f"\n{'='*50}")
    print(f" {APP_NAME} v{APP_VERSION}")
    print(f" 起動時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")

    logger.info(f"{APP_NAME} v{APP_VERSION} 起動")

    # 設定読み込み
    config = load_config()
    logger.info(f"監視フォルダ: {config['paths']['mail_data_dir']}")

    # 監視フォルダの存在確認
    mail_dir = config['paths']['mail_data_dir']
    if not os.path.exists(mail_dir):
        logger.error(f"メールフォルダが見つかりません: {mail_dir}")
        logger.error("config.json の paths.mail_data_dir を確認してください")
        input("Enterキーで終了...")
        sys.exit(1)

    # Updaterの初期化
    updater = AutoUpdater(config, BASE_DIR)

    # --status オプション
    if args.status:
        status = updater.get_status()
        print("=== 更新設定 ===")
        for k, v in status.items():
            print(f"  {k}: {v}")
        print(f"\n=== 監視設定 ===")
        print(f"  監視フォルダ: {mail_dir}")
        print(f"  スキャン間隔: {config['monitor'].get('scan_interval_seconds', 5)}秒")
        sys.exit(0)

    # 強制更新
    if args.update:
        logger.info("強制更新を実行します...")
        updated, files = updater.force_update()
        if updated:
            logger.info(f"更新完了: {files}")
        else:
            logger.info("更新なし（またはGitHub未設定）")

    # --no-update オプション
    if args.no_update:
        config['update']['enabled'] = False

    # 監視モジュールの初期化
    monitor = MailMonitor(config, BASE_DIR)

    # --scan-only オプション（一度だけスキャンして終了）
    if args.scan_only:
        logger.info("スキャンのみモードで実行")
        monitor.start()
        time.sleep(2)
        monitor.stop()
        logger.info("スキャン完了")
        return

    # 常駐監視モードで起動
    if not monitor.start():
        logger.error("監視の起動に失敗しました")
        input("Enterキーで終了...")
        sys.exit(1)

    # 起動通知
    notify_startup(APP_NAME)
    logger.info("監視を開始しました。Ctrl+C で停止します。")

    # 自動更新バックグラウンドスレッド
    update_enabled = config.get('update', {}).get('enabled', True)
    if update_enabled and not args.no_update:
        # 起動時に最初の更新チェックを実行
        try:
            updated, files = updater.check_and_update_rules()
            if updated:
                monitor.reload_rules()
                notify_update(APP_NAME, files)
                logger.info(f"起動時更新完了: {files}")
        except Exception as e:
            logger.debug(f"起動時更新スキップ: {e}")

        # 定期更新スレッドを起動
        interval = config.get('update', {}).get('check_interval_hours', 24)
        update_thread = threading.Thread(
            target=run_update_loop,
            args=(updater, monitor, interval),
            daemon=True
        )
        update_thread.start()
        logger.info(f"自動更新スレッド起動 (間隔: {interval}時間)")

    # [改善] シグナルハンドラー設定（Windows互換）
    def shutdown(signum, frame):
        logger.info("シャットダウン要求を受信")
        monitor.stop()
        logger.info(f"{APP_NAME} を停止しました")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    # SIGTERM は Windows では未サポートのため条件付きで登録
    if hasattr(signal, 'SIGTERM'):
        try:
            signal.signal(signal.SIGTERM, shutdown)
        except (OSError, ValueError):
            pass  # Windows では無視

    # メインループ
    try:
        while True:
            time.sleep(1)
            if not monitor.is_running():
                logger.warning("監視プロセスが停止しました。再起動します...")
                time.sleep(5)
                monitor.start()
    except KeyboardInterrupt:
        logger.info("キーボード割り込みで停止")
        monitor.stop()

    logger.info(f"{APP_NAME} 終了")


if __name__ == '__main__':
    main()
