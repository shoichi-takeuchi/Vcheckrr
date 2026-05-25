"""
monitor.py - メールフォルダ常駐監視モジュール
watchdogを使ってTuruKameDataフォルダを監視し、新着メールを自動検知する
"""
import os
import time
import json
import logging
import threading
from typing import Set
from datetime import datetime, timedelta

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from email_parser import parse_email_file, is_mail_file
from detector import PhishingDetector, DetectionResult
from notifier import PhishingNotifier

logger = logging.getLogger(__name__)


class MailEventHandler(FileSystemEventHandler):
    """メールファイル変更イベントハンドラー"""

    def __init__(self, detector: PhishingDetector, notifier: PhishingNotifier,
                 log_writer, config: dict):
        super().__init__()
        self.detector = detector
        self.notifier = notifier
        self.log_writer = log_writer
        self.config = config
        self._processed: Set[str] = set()  # 処理済みファイルのキャッシュ
        self._lock = threading.Lock()

    def _process_file(self, file_path: str):
        """メールファイルを処理する"""
        with self._lock:
            # 処理済みチェック（短時間の重複イベント防止）
            if file_path in self._processed:
                return
            self._processed.add(file_path)

        try:
            # ファイルが完全に書き込まれるまで少し待つ
            time.sleep(0.5)

            if not os.path.exists(file_path):
                return

            if not is_mail_file(file_path):
                return

            logger.debug(f"メールファイル検知: {file_path}")

            # メールを解析
            parsed = parse_email_file(file_path)

            # フィッシング検知
            result = self.detector.detect(parsed)

            # 警告以上の場合は通知
            if result.risk_level in ('warning', 'danger'):
                self.notifier.notify(result)
                logger.warning(
                    f"[{result.risk_level.upper()}] スコア={result.score} "
                    f"件名: {result.subject[:60]}"
                )

            # ログに記録
            if self.log_writer:
                self.log_writer(result)

        except Exception as e:
            logger.error(f"ファイル処理エラー [{file_path}]: {e}")
        finally:
            # 処理済みキャッシュは一定時間後にクリア（同じファイルの再処理を許可）
            threading.Timer(60.0, lambda: self._processed.discard(file_path)).start()

    def on_created(self, event):
        """ファイル作成イベント"""
        if not event.is_directory:
            self._process_file(event.src_path)

    def on_modified(self, event):
        """ファイル変更イベント（秀丸メールは受信時に既存ファイルを更新する場合あり）"""
        if not event.is_directory:
            self._process_file(event.src_path)


class PollingMonitor:
    """
    watchdog非対応時のポーリングモニター
    定期的にフォルダをスキャンして新着メールを検知する
    """

    def __init__(self, watch_dir: str, detector: PhishingDetector,
                 notifier: PhishingNotifier, log_writer, config: dict):
        self.watch_dir = watch_dir
        self.detector = detector
        self.notifier = notifier
        self.log_writer = log_writer
        self.config = config
        self._known_files: dict = {}  # {filepath: mtime}
        self._running = False
        self._thread = None

    def _scan(self):
        """フォルダをスキャンして新着・変更ファイルを検知"""
        monitor_config = self.config.get('monitor', {})
        max_age = monitor_config.get('max_file_age_hours', 24)
        cutoff = datetime.now() - timedelta(hours=max_age)

        for root, _, files in os.walk(self.watch_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    mtime = stat.st_mtime

                    # 古いファイルはスキップ
                    if datetime.fromtimestamp(mtime) < cutoff:
                        continue

                    # 新着または変更されたファイル
                    prev_mtime = self._known_files.get(fpath)
                    if prev_mtime is None or prev_mtime != mtime:
                        self._known_files[fpath] = mtime
                        if is_mail_file(fpath):
                            self._process_file(fpath)

                except OSError:
                    pass

    def _process_file(self, file_path: str):
        """メールファイルを処理する"""
        try:
            parsed = parse_email_file(file_path)
            result = self.detector.detect(parsed)

            if result.risk_level in ('warning', 'danger'):
                self.notifier.notify(result)
                logger.warning(
                    f"[{result.risk_level.upper()}] スコア={result.score} "
                    f"件名: {result.subject[:60]}"
                )

            if self.log_writer:
                self.log_writer(result)

        except Exception as e:
            logger.error(f"ファイル処理エラー [{file_path}]: {e}")

    def _run(self):
        """ポーリングループ"""
        interval = self.config.get('monitor', {}).get('scan_interval_seconds', 5)
        while self._running:
            try:
                self._scan()
            except Exception as e:
                logger.error(f"スキャンエラー: {e}")
            time.sleep(interval)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"ポーリングモニター開始: {self.watch_dir}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("ポーリングモニター停止")


class MailMonitor:
    """
    メール監視マネージャー
    watchdog優先、非対応時はポーリングにフォールバック
    """

    def __init__(self, config: dict, base_dir: str):
        self.config = config
        self.base_dir = base_dir
        self.monitor_config = config.get('monitor', {})
        self.watch_dir = config['paths']['mail_data_dir']
        self.log_path = os.path.join(base_dir, config['paths']['log_file'])

        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        os.makedirs(os.path.join(base_dir, 'logs'), exist_ok=True)

        # 検知・通知モジュールの初期化
        rules_dir = os.path.join(base_dir, config['paths']['rules_dir'])
        self.detector = PhishingDetector(rules_dir, config)
        self.notifier = PhishingNotifier(config)

        self._observer = None
        self._polling_monitor = None
        self._running = False

        # 起動時スキャン済みファイルの追跡
        self._startup_scanned: Set[str] = set()

    def _write_log(self, result: DetectionResult):
        """検知結果をログファイルに書き込む"""
        if not self.config.get('notification', {}).get('log_to_file', True):
            return

        if result.risk_level == 'safe':
            return

        try:
            log_entry = {
                'timestamp': result.timestamp,
                'risk_level': result.risk_level,
                'score': result.score,
                'subject': result.subject,
                'from_address': result.from_address,
                'from_display_name': result.from_display_name,
                'file_path': result.file_path,
                'reasons': result.reasons,
                'suspicious_urls': result.suspicious_urls
            }
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"ログ書き込みエラー: {e}")

    def _scan_existing_files(self):
        """起動時に既存のメールファイルをスキャンする"""
        if not self.monitor_config.get('scan_existing_on_start', True):
            return

        max_age = self.monitor_config.get('max_file_age_hours', 24)
        cutoff = datetime.now() - timedelta(hours=max_age)

        logger.info(f"起動時スキャン開始 (過去{max_age}時間分)")
        count = 0

        for root, _, files in os.walk(self.watch_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    if datetime.fromtimestamp(stat.st_mtime) >= cutoff:
                        if is_mail_file(fpath):
                            parsed = parse_email_file(fpath)
                            result = self.detector.detect(parsed)
                            self._startup_scanned.add(fpath)

                            if result.risk_level in ('warning', 'danger'):
                                self.notifier.notify(result)
                                logger.warning(
                                    f"[起動時スキャン][{result.risk_level.upper()}] "
                                    f"スコア={result.score} 件名: {result.subject[:60]}"
                                )
                                self._write_log(result)
                            count += 1

                except Exception as e:
                    logger.debug(f"スキャンエラー [{fpath}]: {e}")

        logger.info(f"起動時スキャン完了: {count}件処理")

    def start(self):
        """監視を開始する"""
        if not os.path.exists(self.watch_dir):
            logger.error(f"監視フォルダが見つかりません: {self.watch_dir}")
            logger.error("config.json の paths.mail_data_dir を確認してください")
            return False

        self._running = True
        logger.info(f"監視開始: {self.watch_dir}")

        # 起動時スキャン
        self._scan_existing_files()

        # watchdogが利用可能か確認
        if WATCHDOG_AVAILABLE:
            try:
                handler = MailEventHandler(
                    self.detector, self.notifier, self._write_log, self.config
                )
                self._observer = Observer()
                self._observer.schedule(handler, self.watch_dir, recursive=True)
                self._observer.start()
                logger.info("watchdog監視モードで起動")
                return True
            except Exception as e:
                logger.warning(f"watchdog起動失敗、ポーリングモードに切り替え: {e}")

        # ポーリングモードにフォールバック
        self._polling_monitor = PollingMonitor(
            self.watch_dir, self.detector, self.notifier, self._write_log, self.config
        )
        self._polling_monitor.start()
        logger.info("ポーリング監視モードで起動")
        return True

    def stop(self):
        """監視を停止する"""
        self._running = False

        if self._observer:
            self._observer.stop()
            self._observer.join()
            logger.info("watchdog監視停止")

        if self._polling_monitor:
            self._polling_monitor.stop()

        logger.info("監視停止完了")

    def reload_rules(self):
        """ルールを再読み込みする"""
        self.detector.reload_rules()
        logger.info("検知ルールを再読み込みしました")

    def is_running(self) -> bool:
        """監視が実行中か確認"""
        if self._observer:
            return self._observer.is_alive()
        if self._polling_monitor:
            return self._polling_monitor._running
        return False
