"""
notifier.py - Windowsポップアップ通知モジュール
win10toast または winotify を使用してトースト通知を表示する
"""
import os
import sys
import time
import logging
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional, Set
from detector import DetectionResult

logger = logging.getLogger(__name__)


class PhishingNotifier:
    """フィッシング警告通知クラス"""

    def __init__(self, config: dict):
        self.config = config
        self.notif_config = config.get('notification', {})
        self._toast_available = self._check_toast()
        # [追加] 重複通知防止: 通知済みファイルパスのキャッシュ（TTL付き）
        self._notified: dict = {}   # {file_path: timestamp}
        self._notified_lock = threading.Lock()
        self._NOTIFY_TTL = 300      # 同じファイルは5分間は再通知しない

    def _check_toast(self) -> bool:
        """Windowsトースト通知が利用可能か確認"""
        try:
            from winotify import Notification
            return True
        except ImportError:
            pass
        try:
            from win10toast import ToastNotifier
            return True
        except ImportError:
            pass
        return False

    def _send_toast(self, title: str, message: str, icon_type: str = "warning"):
        """Windowsトースト通知を送信する"""
        # winotifyを優先的に使用
        try:
            from winotify import Notification, audio

            toast = Notification(
                app_id="秀丸メール フィッシング検知",
                title=title,
                msg=message[:256],
                duration="long",
                icon=self._get_icon_path(icon_type)
            )
            if self.notif_config.get('play_sound', True):
                toast.set_audio(audio.Default, loop=False)
            toast.show()
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"winotify エラー: {e}")

        # win10toastにフォールバック
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(
                title,
                message[:256],
                icon_path=self._get_icon_path(icon_type),
                duration=self.notif_config.get('notification_timeout_seconds', 10),
                threaded=True
            )
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"win10toast エラー: {e}")

        return False

    def _get_icon_path(self, icon_type: str) -> Optional[str]:
        """アイコンファイルのパスを返す"""
        icon_dir = os.path.join(os.path.dirname(__file__), 'icons')
        icon_file = os.path.join(icon_dir, f'{icon_type}.ico')
        if os.path.exists(icon_file):
            return icon_file
        return None

    def _show_detail_dialog(self, result: DetectionResult):
        """詳細情報ダイアログを表示する（別スレッドで実行）"""
        def _show():
            root = tk.Tk()
            root.withdraw()  # メインウィンドウを非表示

            if result.risk_level == "danger":
                bg_color = "#FF4444"
                title_text = "🚨 危険：フィッシングメールの可能性が高い"
            else:
                bg_color = "#FF8C00"
                title_text = "⚠️ 警告：フィッシングメールの疑いがあります"

            # カスタムダイアログ作成
            dialog = tk.Toplevel(root)
            dialog.title("フィッシングメール警告")
            dialog.geometry("600x500")
            dialog.resizable(True, True)
            dialog.attributes('-topmost', True)  # 最前面に表示
            dialog.grab_set()

            # ヘッダー
            header_frame = tk.Frame(dialog, bg=bg_color, pady=10)
            header_frame.pack(fill='x')
            tk.Label(
                header_frame,
                text=title_text,
                bg=bg_color,
                fg='white',
                font=('Yu Gothic UI', 12, 'bold'),
                wraplength=560
            ).pack(padx=10)

            # スコア表示
            score_frame = tk.Frame(dialog, pady=5)
            score_frame.pack(fill='x', padx=10)
            tk.Label(
                score_frame,
                text=f"危険スコア: {result.score}点",
                font=('Yu Gothic UI', 11, 'bold'),
                fg=bg_color
            ).pack(side='left')

            # メール情報
            info_frame = ttk.LabelFrame(dialog, text="メール情報", padding=8)
            info_frame.pack(fill='x', padx=10, pady=5)

            fields = [
                ("件名", result.subject or "(件名なし)"),
                ("送信者", result.from_address or "(不明)"),
                ("表示名", result.from_display_name or "(なし)"),
                ("ファイル", os.path.basename(result.file_path)),
            ]
            for label, value in fields:
                row = tk.Frame(info_frame)
                row.pack(fill='x', pady=1)
                tk.Label(row, text=f"{label}:", width=8, anchor='w',
                         font=('Yu Gothic UI', 9, 'bold')).pack(side='left')
                tk.Label(row, text=str(value)[:80], anchor='w',
                         font=('Yu Gothic UI', 9)).pack(side='left')

            # 検知理由
            reasons_frame = ttk.LabelFrame(dialog, text="検知された問題点", padding=8)
            reasons_frame.pack(fill='both', expand=True, padx=10, pady=5)

            reasons_text = tk.Text(reasons_frame, height=8, wrap='word',
                                   font=('Yu Gothic UI', 9))
            scrollbar = ttk.Scrollbar(reasons_frame, command=reasons_text.yview)
            reasons_text.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side='right', fill='y')
            reasons_text.pack(fill='both', expand=True)

            for i, reason in enumerate(result.reasons, 1):
                reasons_text.insert('end', f"• {reason}\n")
            reasons_text.config(state='disabled')

            # 注意書き
            note_text = (
                "⚠️ このメールのリンクをクリックしないでください。\n"
                "心当たりがない場合は送信者に別の手段で確認してください。"
            )
            tk.Label(
                dialog,
                text=note_text,
                fg="#CC0000",
                font=('Yu Gothic UI', 9),
                justify='left',
                wraplength=560
            ).pack(padx=10, pady=5)

            # ボタン
            btn_frame = tk.Frame(dialog, pady=8)
            btn_frame.pack()
            tk.Button(
                btn_frame,
                text="閉じる",
                command=dialog.destroy,
                width=12,
                font=('Yu Gothic UI', 10),
                bg='#555555',
                fg='white',
                cursor='hand2'
            ).pack(side='left', padx=5)

            dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
            dialog.wait_window()
            root.destroy()

        # 別スレッドで実行（メインスレッドをブロックしない）
        thread = threading.Thread(target=_show, daemon=True)
        thread.start()

    def _is_duplicate(self, file_path: str) -> bool:
        """[追加] 重複通知チェック"""
        now = time.time()
        with self._notified_lock:
            # 期限切れキャッシュを掃除
            expired = [k for k, t in self._notified.items() if now - t > self._NOTIFY_TTL]
            for k in expired:
                del self._notified[k]
            # 既に通知済みか確認
            if file_path in self._notified:
                return True
            self._notified[file_path] = now
            return False

    def notify(self, result: DetectionResult):
        """検知結果に応じて通知を送信する"""
        if not self.notif_config.get('enabled', True):
            return

        if result.risk_level == "safe":
            return

        if result.risk_level == "danger" and not self.notif_config.get('show_danger', True):
            return
        if result.risk_level == "warning" and not self.notif_config.get('show_warning', True):
            return

        # [追加] 重複通知防止
        if self._is_duplicate(result.file_path):
            logger.debug(f"重複通知スキップ: {result.file_path}")
            return

        # リスクレベルに応じたメッセージ作成
        if result.risk_level == "danger":
            emoji = "🚨"
            level_text = "危険"
            icon_type = "danger"
        else:
            emoji = "⚠️"
            level_text = "警告"
            icon_type = "warning"

        subject_short = result.subject[:40] + "..." if len(result.subject) > 40 else result.subject
        sender_short = result.from_address[:40]

        toast_title = f"{emoji} フィッシングメール{level_text} (スコア:{result.score})"
        toast_msg = f"件名: {subject_short}\n送信者: {sender_short}"

        # トースト通知を送信
        toast_sent = False
        if self._toast_available:
            toast_sent = self._send_toast(toast_title, toast_msg, icon_type)

        # 詳細ダイアログを表示
        if self.notif_config.get('show_detail_dialog', True) and result.score >= 60:
            self._show_detail_dialog(result)

        logger.info(f"通知送信: [{level_text}] {subject_short} (トースト: {toast_sent})")


def notify_startup(app_name: str):
    """起動通知を表示する"""
    try:
        from winotify import Notification
        toast = Notification(
            app_id=app_name,
            title=f"✅ {app_name}",
            msg="フィッシングメール監視を開始しました",
            duration="short"
        )
        toast.show()
    except ImportError:
        pass
    except Exception:
        pass


def notify_update(app_name: str, updated_files: list):
    """更新通知を表示する"""
    try:
        from winotify import Notification
        files_text = ', '.join(updated_files[:3])
        if len(updated_files) > 3:
            files_text += f" 他{len(updated_files)-3}件"
        toast = Notification(
            app_id=app_name,
            title=f"🔄 {app_name} - 更新完了",
            msg=f"検知ルールを更新しました: {files_text}",
            duration="short"
        )
        toast.show()
    except ImportError:
        pass
    except Exception:
        pass
