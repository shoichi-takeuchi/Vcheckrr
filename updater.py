"""
updater.py - GitHubからの自動更新モジュール
検知ルール（JSONファイル）とスクリプト本体の自動更新を管理する
"""
import os
import sys
import json
import hashlib
import logging
import urllib.request
import urllib.error
import shutil
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)

# GitHubのRaw URLベース
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/{repo}/{branch}"

# 更新対象ファイルリスト（rules/以下のルールファイル）
RULE_FILES = [
    "rules/keywords.json",
    "rules/domains.json",
    "rules/patterns.json",
]

# アプリ更新対象ファイル（auto_update_app=Trueの場合）
APP_FILES = [
    "email_parser.py",
    "detector.py",
    "notifier.py",
    "monitor.py",
    "updater.py",
    "main.py",
]

VERSION_FILE = "version.json"


class AutoUpdater:
    """GitHub連携自動更新クラス"""

    def __init__(self, config: dict, base_dir: str):
        self.config = config
        self.base_dir = base_dir
        self.update_config = config.get('update', {})
        self.config_path = os.path.join(base_dir, 'config.json')

    @property
    def github_repo(self) -> str:
        return self.update_config.get('github_repo', '')

    @property
    def github_branch(self) -> str:
        return self.update_config.get('github_branch', 'main')

    @property
    def raw_base_url(self) -> str:
        return GITHUB_RAW_BASE.format(
            repo=self.github_repo,
            branch=self.github_branch
        )

    def _should_check(self) -> bool:
        """更新チェックが必要か判断する"""
        if not self.update_config.get('enabled', True):
            return False

        last_check = self.update_config.get('last_check')
        if not last_check:
            return True

        try:
            last_dt = datetime.fromisoformat(last_check)
            interval_hours = self.update_config.get('check_interval_hours', 24)
            return datetime.now() - last_dt > timedelta(hours=interval_hours)
        except (ValueError, TypeError):
            return True

    def _fetch_url(self, url: str, timeout: int = 15) -> Optional[bytes]:
        """URLからコンテンツを取得する"""
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'HidemarPhishingDetector/1.0'}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code != 404:
                logger.debug(f"HTTP エラー {e.code}: {url}")
        except urllib.error.URLError as e:
            logger.debug(f"URL エラー: {url} - {e.reason}")
        except Exception as e:
            logger.debug(f"取得エラー: {url} - {e}")
        return None

    def _get_file_hash(self, file_path: str) -> str:
        """ファイルのSHA256ハッシュを計算する"""
        if not os.path.exists(file_path):
            return ""
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            h.update(f.read())
        return h.hexdigest()

    def _get_content_hash(self, content: bytes) -> str:
        """バイトデータのSHA256ハッシュを計算する"""
        return hashlib.sha256(content).hexdigest()

    def _backup_file(self, file_path: str):
        """ファイルのバックアップを作成する"""
        if not os.path.exists(file_path):
            return
        backup_dir = os.path.join(self.base_dir, 'backup')
        os.makedirs(backup_dir, exist_ok=True)
        backup_name = os.path.basename(file_path) + '.bak'
        shutil.copy2(file_path, os.path.join(backup_dir, backup_name))

    def _save_file(self, file_path: str, content: bytes):
        """ファイルを保存する（バックアップ付き）"""
        full_path = os.path.join(self.base_dir, file_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        self._backup_file(full_path)
        with open(full_path, 'wb') as f:
            f.write(content)
        logger.info(f"更新完了: {file_path}")

    def _update_last_check(self):
        """最終チェック日時を記録する"""
        self.update_config['last_check'] = datetime.now().isoformat()
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            config_data['update']['last_check'] = self.update_config['last_check']
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.debug(f"設定ファイル更新エラー: {e}")

    def _update_last_update(self):
        """最終更新日時を記録する"""
        self.update_config['last_update'] = datetime.now().isoformat()
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            config_data['update']['last_update'] = self.update_config['last_update']
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.debug(f"設定ファイル更新エラー: {e}")

    def check_and_update_rules(self) -> Tuple[bool, List[str]]:
        """
        GitHubからルールファイルの更新を確認・適用する
        Returns: (更新があったか, 更新されたファイルリスト)
        """
        if not self.github_repo or self.github_repo == 'your-github-username/hidemaru-phishing-rules':
            logger.info("GitHubリポジトリが設定されていません。config.jsonの update.github_repo を設定してください。")
            return False, []

        if not self._should_check():
            logger.debug("更新チェック間隔内のためスキップ")
            return False, []

        logger.info(f"更新確認中: {self.github_repo}")
        updated_files = []

        try:
            # バージョン情報を先にチェック
            version_url = f"{self.raw_base_url}/{VERSION_FILE}"
            version_content = self._fetch_url(version_url)

            if version_content:
                try:
                    remote_version = json.loads(version_content.decode('utf-8'))
                    logger.info(f"リモートバージョン: {remote_version.get('rules_version', '不明')}")
                except json.JSONDecodeError:
                    pass

            # ルールファイルの更新チェック
            if self.update_config.get('auto_update_rules', True):
                for rel_path in RULE_FILES:
                    url = f"{self.raw_base_url}/{rel_path}"
                    content = self._fetch_url(url)

                    if content is None:
                        continue

                    local_path = os.path.join(self.base_dir, rel_path)
                    local_hash = self._get_file_hash(local_path)
                    remote_hash = self._get_content_hash(content)

                    if local_hash != remote_hash:
                        logger.info(f"更新あり: {rel_path}")

                        # JSONとして有効か検証
                        try:
                            json.loads(content.decode('utf-8'))
                        except json.JSONDecodeError as e:
                            logger.error(f"JSONエラー（スキップ）: {rel_path} - {e}")
                            continue

                        self._save_file(rel_path, content)
                        updated_files.append(rel_path)
                    else:
                        logger.debug(f"変更なし: {rel_path}")

            # アプリファイルの更新チェック（オプション）
            if self.update_config.get('auto_update_app', False):
                for rel_path in APP_FILES:
                    url = f"{self.raw_base_url}/{rel_path}"
                    content = self._fetch_url(url)

                    if content is None:
                        continue

                    local_path = os.path.join(self.base_dir, rel_path)
                    local_hash = self._get_file_hash(local_path)
                    remote_hash = self._get_content_hash(content)

                    if local_hash != remote_hash:
                        logger.info(f"アプリ更新あり: {rel_path}")
                        self._save_file(rel_path, content)
                        updated_files.append(rel_path)

        except Exception as e:
            logger.error(f"更新チェックエラー: {e}")
        finally:
            self._update_last_check()

        if updated_files:
            self._update_last_update()
            logger.info(f"更新完了: {len(updated_files)}件のファイルを更新")

        return len(updated_files) > 0, updated_files

    def force_update(self) -> Tuple[bool, List[str]]:
        """強制更新（間隔チェックをスキップ）"""
        # 最終チェック日時をリセットして即時更新
        self.update_config['last_check'] = None
        return self.check_and_update_rules()

    def get_status(self) -> dict:
        """更新ステータスを返す"""
        return {
            'enabled': self.update_config.get('enabled', True),
            'github_repo': self.github_repo,
            'github_branch': self.github_branch,
            'last_check': self.update_config.get('last_check', '未実施'),
            'last_update': self.update_config.get('last_update', '未実施'),
            'check_interval_hours': self.update_config.get('check_interval_hours', 24),
            'auto_update_rules': self.update_config.get('auto_update_rules', True),
            'auto_update_app': self.update_config.get('auto_update_app', False),
        }


def create_version_file(base_dir: str, version: str = "1.0.0"):
    """バージョンファイルを作成する（GitHubリポジトリ管理用）"""
    version_data = {
        "app_version": version,
        "rules_version": version,
        "updated": datetime.now().strftime('%Y-%m-%d'),
        "changelog": [
            f"{version}: 初回リリース"
        ]
    }
    version_path = os.path.join(base_dir, VERSION_FILE)
    with open(version_path, 'w', encoding='utf-8') as f:
        json.dump(version_data, f, ensure_ascii=False, indent=2)
    logger.info(f"バージョンファイル作成: {version_path}")
