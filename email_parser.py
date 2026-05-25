"""
email_parser.py - 秀丸メール形式のメールファイルを解析するモジュール
秀丸メールはメールをeml形式（RFC 2822準拠）で保存する
"""
import os
import re
import email
import email.header
import email.utils
import chardet
import logging
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ParsedEmail:
    """解析済みメールデータクラス"""
    file_path: str = ""
    message_id: str = ""
    subject: str = ""
    from_address: str = ""
    from_display_name: str = ""
    to_address: str = ""
    reply_to_address: str = ""          # [追加] Reply-Toアドレス
    date: str = ""
    body_text: str = ""
    body_html: str = ""
    urls: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    raw_content: str = ""
    parse_error: Optional[str] = None
    # [追加] メール認証情報
    spf_result: str = ""                # pass / fail / softfail / neutral / none
    dkim_result: str = ""               # pass / fail / none
    dmarc_result: str = ""              # pass / fail / none
    auth_results_raw: str = ""          # Authentication-Results ヘッダー生値


def _parse_auth_result(auth_header: str, mechanism: str) -> str:
    """
    Authentication-Results ヘッダーから指定メカニズムの結果を取得する
    例: "spf=pass", "dkim=fail", "dmarc=none"
    """
    pattern = re.compile(
        rf'\b{mechanism}=(\w+)',
        re.IGNORECASE
    )
    m = pattern.search(auth_header)
    if m:
        return m.group(1).lower()
    return "none"


def decode_header_value(value: str) -> str:
    """メールヘッダーの文字列をデコードする"""
    if not value:
        return ""
    try:
        decoded_parts = email.header.decode_header(value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                if charset:
                    try:
                        result.append(part.decode(charset, errors='replace'))
                    except (LookupError, UnicodeDecodeError):
                        # chardetで文字コードを推定
                        detected = chardet.detect(part)
                        enc = detected.get('encoding', 'utf-8') or 'utf-8'
                        result.append(part.decode(enc, errors='replace'))
                else:
                    # 文字コード未指定の場合はchardetで推定
                    detected = chardet.detect(part)
                    enc = detected.get('encoding', 'utf-8') or 'utf-8'
                    result.append(part.decode(enc, errors='replace'))
            else:
                result.append(str(part))
        return " ".join(result)
    except Exception as e:
        logger.debug(f"ヘッダーデコードエラー: {e}")
        return str(value)


def extract_urls_from_text(text: str) -> list:
    """テキストからURLを抽出する"""
    import re
    url_pattern = re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    # 末尾の不要な文字を除去
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if url not in cleaned:
            cleaned.append(url)
    return cleaned


def extract_urls_from_html(html: str) -> list:
    """HTMLからURLを抽出する（href属性など）"""
    import re
    urls = []

    # href属性
    href_pattern = re.compile(r'href=["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)
    urls.extend(href_pattern.findall(html))

    # action属性（フォーム）
    action_pattern = re.compile(r'action=["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)
    urls.extend(action_pattern.findall(html))

    # src属性
    src_pattern = re.compile(r'src=["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)
    urls.extend(src_pattern.findall(html))

    # テキスト内のURL
    urls.extend(extract_urls_from_text(html))

    # 重複除去
    return list(dict.fromkeys(urls))


def decode_payload(part) -> str:
    """メールパートのペイロードをデコードする"""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""

    # 文字コードを取得
    charset = part.get_content_charset()

    if charset:
        try:
            return payload.decode(charset, errors='replace')
        except (LookupError, UnicodeDecodeError):
            pass

    # chardetで自動検出
    detected = chardet.detect(payload)
    enc = detected.get('encoding') or 'utf-8'
    try:
        return payload.decode(enc, errors='replace')
    except Exception:
        return payload.decode('utf-8', errors='replace')


def parse_email_file(file_path: str) -> ParsedEmail:
    """
    メールファイルを解析してParsedEmailオブジェクトを返す
    秀丸メールはeml形式（RFC 2822）でメールを保存する
    """
    result = ParsedEmail(file_path=file_path)

    try:
        # ファイルを読み込む（文字コード自動検出）
        with open(file_path, 'rb') as f:
            raw_bytes = f.read()

        # chardetで文字コードを検出
        detected = chardet.detect(raw_bytes[:4096])
        enc = detected.get('encoding') or 'utf-8'

        try:
            raw_content = raw_bytes.decode(enc, errors='replace')
        except Exception:
            raw_content = raw_bytes.decode('utf-8', errors='replace')

        result.raw_content = raw_content

        # emailモジュールで解析
        msg = email.message_from_bytes(raw_bytes)

        # ヘッダー情報を取得
        result.message_id = decode_header_value(msg.get('Message-ID', ''))
        result.subject = decode_header_value(msg.get('Subject', '件名なし'))
        result.date = msg.get('Date', '')

        # 送信者情報
        from_raw = msg.get('From', '')
        from_name, from_email = email.utils.parseaddr(from_raw)
        result.from_address = from_email
        result.from_display_name = decode_header_value(from_name) if from_name else ""

        # [追加] Reply-Toアドレスの解析
        reply_to_raw = msg.get('Reply-To', '')
        if reply_to_raw:
            _, reply_to_email = email.utils.parseaddr(reply_to_raw)
            result.reply_to_address = reply_to_email

        # 宛先
        to_raw = msg.get('To', '')
        _, to_email = email.utils.parseaddr(to_raw)
        result.to_address = to_email

        # [追加] Authentication-Results ヘッダーの解析（SPF/DKIM/DMARC）
        auth_results = msg.get('Authentication-Results', '')
        if auth_results:
            result.auth_results_raw = auth_results
            result.spf_result = _parse_auth_result(auth_results, 'spf')
            result.dkim_result = _parse_auth_result(auth_results, 'dkim')
            result.dmarc_result = _parse_auth_result(auth_results, 'dmarc')

        # 全ヘッダーを保存
        for key in msg.keys():
            result.headers[key] = decode_header_value(msg.get(key, ''))

        # 本文を取得
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                # 添付ファイルはスキップ
                if 'attachment' in content_disposition:
                    continue

                if content_type == 'text/plain':
                    text = decode_payload(part)
                    if text:
                        result.body_text += text

                elif content_type == 'text/html':
                    html = decode_payload(part)
                    if html:
                        result.body_html += html
        else:
            content_type = msg.get_content_type()
            payload_text = decode_payload(msg)

            if content_type == 'text/html':
                result.body_html = payload_text
            else:
                result.body_text = payload_text

        # URLを抽出
        all_urls = []
        if result.body_text:
            all_urls.extend(extract_urls_from_text(result.body_text))
        if result.body_html:
            all_urls.extend(extract_urls_from_html(result.body_html))

        # 重複除去
        result.urls = list(dict.fromkeys(all_urls))

    except Exception as e:
        result.parse_error = str(e)
        logger.error(f"メール解析エラー [{file_path}]: {e}")

    return result


def is_mail_file(file_path: str) -> bool:
    """
    ファイルがメールファイルかどうか判定する
    秀丸メールは .eml 拡張子または拡張子なしのファイルに保存する場合がある
    """
    if not os.path.isfile(file_path):
        return False

    ext = os.path.splitext(file_path)[1].lower()
    if ext in ('.eml', '.msg'):
        return True

    # 拡張子なしのファイルはヘッダーをチェック
    if ext == '':
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
            # RFC 2822形式のヘッダーを持つか確認
            header_str = header.decode('utf-8', errors='ignore')
            return any(h in header_str for h in [
                'From:', 'To:', 'Subject:', 'Message-ID:',
                'Date:', 'MIME-Version:', 'Content-Type:'
            ])
        except Exception:
            return False

    return False
