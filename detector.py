"""
detector.py - フィッシングメール検知モジュール
スコアリングベースの多段階検知システム
"""
import re
import json
import os
import logging
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Tuple
from email_parser import ParsedEmail

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """検知結果データクラス"""
    file_path: str = ""
    subject: str = ""
    from_address: str = ""
    from_display_name: str = ""
    score: int = 0
    risk_level: str = "safe"   # safe / warning / danger
    reasons: List[str] = field(default_factory=list)
    suspicious_urls: List[str] = field(default_factory=list)
    timestamp: str = ""


class PhishingDetector:
    """フィッシングメール検知クラス"""

    def __init__(self, rules_dir: str, config: dict):
        self.rules_dir = rules_dir
        self.config = config
        self.keywords = {}
        self.domains = {}
        self.patterns = {}
        self.scoring = {}
        self._load_rules()

    def _load_rules(self):
        """ルールファイルを読み込む"""
        try:
            with open(os.path.join(self.rules_dir, 'keywords.json'), encoding='utf-8') as f:
                self.keywords = json.load(f)
            with open(os.path.join(self.rules_dir, 'domains.json'), encoding='utf-8') as f:
                self.domains = json.load(f)
            with open(os.path.join(self.rules_dir, 'patterns.json'), encoding='utf-8') as f:
                self.patterns = json.load(f)
                self.scoring = self.patterns.get('scoring', {})
            logger.info("検知ルールを読み込みました")
        except Exception as e:
            logger.error(f"ルール読み込みエラー: {e}")

    def reload_rules(self):
        """ルールを再読み込みする（更新後に呼ぶ）"""
        self._load_rules()

    def _check_whitelist(self, parsed: ParsedEmail) -> bool:
        """ホワイトリストに該当するか確認"""
        wl = self.config.get('whitelist', {})
        if not wl.get('enabled', True):
            return False

        # 送信者アドレスのチェック
        if parsed.from_address.lower() in [s.lower() for s in wl.get('senders', [])]:
            return True

        # ドメインのチェック
        if '@' in parsed.from_address:
            domain = parsed.from_address.split('@')[1].lower()
            if domain in [d.lower() for d in wl.get('domains', [])]:
                return True

        # 件名のチェック
        for pattern in wl.get('subjects_containing', []):
            if pattern.lower() in parsed.subject.lower():
                return True

        return False

    def _check_subject_keywords(self, subject: str) -> Tuple[int, List[str]]:
        """件名のキーワードチェック"""
        score = 0
        reasons = []
        subject_lower = subject.lower()

        # 日本語キーワード
        kw = self.keywords.get('subject_keywords', {})
        critical_found = [k for k in kw.get('critical', []) if k.lower() in subject_lower]
        warning_found = [k for k in kw.get('warning', []) if k.lower() in subject_lower]

        # [追加] 英語キーワード
        kw_en = self.keywords.get('subject_keywords_en', {})
        critical_found += [k for k in kw_en.get('critical', []) if k.lower() in subject_lower]
        warning_found += [k for k in kw_en.get('warning', []) if k.lower() in subject_lower]

        # スコアに上限を設ける（件名だけで高スコアにならないよう）
        if critical_found:
            add = self.scoring.get('critical_keyword_score', 30) * min(len(critical_found), 2)
            score += add
            reasons.append(f"件名に危険なキーワード: 「{'」「'.join(critical_found[:3])}」")

        if warning_found:
            add = self.scoring.get('warning_keyword_score', 10) * min(len(warning_found), 3)
            score += add
            reasons.append(f"件名に注意キーワード: 「{'」「'.join(warning_found[:3])}」")

        return score, reasons

    def _check_body_keywords(self, body: str) -> Tuple[int, List[str]]:
        """本文のキーワードチェック"""
        score = 0
        reasons = []
        body_lower = body.lower()

        kw = self.keywords.get('body_keywords', {})
        critical_found = [k for k in kw.get('critical', []) if k.lower() in body_lower]
        warning_found = [k for k in kw.get('warning', []) if k.lower() in body_lower]

        # [追加] 英語本文キーワード
        kw_en = self.keywords.get('body_keywords_en', {})
        critical_found += [k for k in kw_en.get('critical', []) if k.lower() in body_lower]
        warning_found += [k for k in kw_en.get('warning', []) if k.lower() in body_lower]

        # 緊急性フレーズ
        urgency_found = []
        for phrase in self.keywords.get('suspicious_patterns', {}).get('urgency_phrases', []):
            if phrase in body_lower:
                urgency_found.append(phrase)

        # 報酬フレーズ
        reward_found = []
        for phrase in self.keywords.get('suspicious_patterns', {}).get('reward_phrases', []):
            if phrase in body_lower:
                reward_found.append(phrase)

        if critical_found:
            score += self.scoring.get('critical_keyword_score', 30) * min(len(critical_found), 3)
            reasons.append(f"本文に危険なキーワード: {', '.join(critical_found[:3])}")

        if warning_found:
            score += self.scoring.get('warning_keyword_score', 10) * min(len(warning_found), 3)
            reasons.append(f"本文に注意キーワード: {', '.join(warning_found[:3])}")

        if urgency_found:
            score += self.scoring.get('urgency_phrase_score', 10)
            reasons.append(f"緊急性を煽る表現: {', '.join(urgency_found[:2])}")

        if reward_found:
            score += self.scoring.get('reward_phrase_score', 15)
            reasons.append(f"当選・報酬を謳う表現: {', '.join(reward_found[:2])}")

        return score, reasons

    def _check_urls(self, urls: List[str]) -> Tuple[int, List[str], List[str]]:
        """URLのチェック"""
        score = 0
        reasons = []
        suspicious_urls = []

        for url in urls[:20]:  # 最大20URL
            url_score = 0
            url_reasons = []

            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                path = parsed_url.path.lower()

                # IPアドレスURL
                if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
                    url_score += self.scoring.get('ip_address_url_score', 40)
                    url_reasons.append("IPアドレスURL")

                # URLショートナー
                for shortener in self.domains.get('url_shorteners', []):
                    if shortener in domain:
                        url_score += self.scoring.get('url_shortener_score', 15)
                        url_reasons.append(f"URLショートナー({shortener})")
                        break

                # 不審なTLD
                for tld in self.domains.get('suspicious_tlds', []):
                    if domain.endswith(tld):
                        url_score += self.scoring.get('suspicious_tld_score', 20)
                        url_reasons.append(f"不審なTLD({tld})")
                        break

                # フィッシングドメインパターン
                for pattern in self.domains.get('known_phishing_patterns', []):
                    if pattern in domain:
                        url_score += self.scoring.get('phishing_domain_pattern_score', 45)
                        url_reasons.append(f"フィッシングドメインパターン({pattern})")
                        break

                # 無料ホスティング
                for hosting in self.domains.get('free_hosting_services', []):
                    if hosting in domain:
                        url_score += self.scoring.get('suspicious_url_score', 25)
                        url_reasons.append(f"無料ホスティング({hosting})")
                        break

                # 不審なパス
                for susp_path in self.patterns.get('url_patterns', {}).get('suspicious_paths', []):
                    if susp_path in path:
                        url_score += 10
                        url_reasons.append(f"不審なパス({susp_path})")
                        break

                # 正規サービスに似た偽ドメイン（サブドメイン偽装）
                for legit in self.domains.get('legitimate_domains', []):
                    legit_base = legit.split('.')[0]
                    # 正規ドメインがサブドメインに含まれているが、正規ドメインではない
                    if legit_base in domain and legit not in domain:
                        url_score += 20
                        url_reasons.append(f"正規サービスを偽装した可能性({legit_base})")
                        break

                # 正規表現パターンチェック
                for pattern in self.patterns.get('url_patterns', {}).get('suspicious_regex', []):
                    try:
                        if re.search(pattern, url, re.IGNORECASE):
                            url_score += self.scoring.get('suspicious_url_score', 25)
                            url_reasons.append(f"不審なURLパターン")
                            break
                    except re.error:
                        pass

            except Exception as e:
                logger.debug(f"URL解析エラー {url}: {e}")

            if url_score > 0:
                suspicious_urls.append(url)
                score += url_score
                for r in url_reasons:
                    reasons.append(f"URL[{url[:50]}...] {r}" if len(url) > 50 else f"URL[{url}] {r}")

        return score, reasons, suspicious_urls

    def _check_sender(self, parsed: ParsedEmail) -> Tuple[int, List[str]]:
        """送信者のチェック"""
        score = 0
        reasons = []

        from_addr = parsed.from_address.lower()
        display_name = parsed.from_display_name

        # 送信者アドレスの正規表現チェック
        for pattern in self.patterns.get('sender_patterns', {}).get('suspicious_regex', []):
            try:
                if re.match(pattern, from_addr, re.IGNORECASE):
                    score += self.scoring.get('suspicious_sender_score', 20)
                    reasons.append(f"不審な送信者アドレスパターン: {from_addr}")
                    break
            except re.error:
                pass

        # 表示名の不一致チェック（なりすまし）
        if display_name and self.patterns.get('sender_patterns', {}).get('display_name_mismatch_check', True):
            spoofed_names = self.patterns.get('sender_patterns', {}).get('known_spoofed_display_names', [])
            for legit_name in spoofed_names:
                if legit_name.lower() in display_name.lower():
                    # 表示名に正規サービス名が含まれているが、送信アドレスが正規ドメインでない
                    is_legit_domain = False
                    for legit_domain in self.domains.get('legitimate_domains', []):
                        if legit_domain in from_addr:
                            is_legit_domain = True
                            break

                    if not is_legit_domain:
                        score += self.scoring.get('display_name_mismatch_score', 35)
                        reasons.append(
                            f"なりすまし疑い: 表示名「{display_name}」に対し送信元は「{from_addr}」"
                        )
                        break

        # [追加] Reply-To と From の不一致チェック
        reply_to = parsed.reply_to_address.lower() if parsed.reply_to_address else ""
        if reply_to and reply_to != from_addr:
            # Reply-To ドメインと From ドメインが異なる場合は不審
            from_domain = from_addr.split('@')[-1] if '@' in from_addr else ""
            reply_domain = reply_to.split('@')[-1] if '@' in reply_to else ""
            if from_domain and reply_domain and from_domain != reply_domain:
                score += self.scoring.get('reply_to_mismatch_score', 25)
                reasons.append(
                    f"Reply-To 不一致: From={from_addr} / Reply-To={reply_to}"
                )

        # [追加] SPF/DKIM 失敗チェック
        spf = getattr(parsed, 'spf_result', 'none')
        dkim = getattr(parsed, 'dkim_result', 'none')
        dmarc = getattr(parsed, 'dmarc_result', 'none')

        if spf in ('fail', 'softfail'):
            score += self.scoring.get('spf_fail_score', 20)
            reasons.append(f"SPF 認証失敗: {spf.upper()}")
        if dkim == 'fail':
            score += self.scoring.get('dkim_fail_score', 20)
            reasons.append("DKIM 署名検証失敗")
        if dmarc == 'fail':
            score += self.scoring.get('dmarc_fail_score', 25)
            reasons.append("DMARC ポリシー違反")

        return score, reasons

    def _check_html_patterns(self, body_html: str) -> Tuple[int, List[str]]:
        """[追加] HTMLパターンチェック（非表示テキスト・偽フォーム）"""
        score = 0
        reasons = []
        html_lower = body_html.lower()

        html_cfg = self.patterns.get('html_patterns', {})

        # 非表示テキスト（スパムフィルタ欺瞞）
        hidden_indicators = html_cfg.get('hidden_text_indicators', [])
        found_hidden = [h for h in hidden_indicators if h in html_lower]
        if found_hidden:
            score += 15
            reasons.append(f"非表示テキスト検知（スパムフィルタ欺瞞の疑い）")

        # HTTP フォームアクション（HTTPSでない送信先）
        suspicious_forms = html_cfg.get('suspicious_form_actions', [])
        for indicator in suspicious_forms:
            if indicator in html_lower:
                score += 20
                reasons.append(f"不審なフォーム送信先（HTTP）")
                break

        # data: URI スキーム（Base64偽装リンク）
        if 'href="data:' in html_lower or "href='data:" in html_lower:
            score += 30
            reasons.append("data: URI リンク検知（偽装リンクの疑い）")

        # javascript: スキーム
        if 'href="javascript:' in html_lower or "href='javascript:" in html_lower:
            score += 20
            reasons.append("JavaScript リンク検知")

        # 過剰な改行・空白による視覚欺瞞
        if html_lower.count('<br') > 50 or html_lower.count('&nbsp;') > 100:
            score += 10
            reasons.append("過剰な改行・空白（視覚欺瞞の疑い）")

        return score, reasons

    def detect(self, parsed: ParsedEmail) -> DetectionResult:
        """メールを解析してフィッシング検知結果を返す"""
        from datetime import datetime

        result = DetectionResult(
            file_path=parsed.file_path,
            subject=parsed.subject,
            from_address=parsed.from_address,
            from_display_name=parsed.from_display_name,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

        # パースエラーの場合はスキップ
        if parsed.parse_error:
            result.risk_level = "unknown"
            result.reasons.append(f"メール解析エラー: {parsed.parse_error}")
            return result

        # ホワイトリストチェック
        if self._check_whitelist(parsed):
            result.risk_level = "safe"
            result.reasons.append("ホワイトリストに登録済み")
            return result

        total_score = 0

        # 件名チェック
        if self.config.get('detection', {}).get('check_subject', True):
            score, reasons = self._check_subject_keywords(parsed.subject)
            total_score += score
            result.reasons.extend(reasons)

        # 本文チェック
        body_text = parsed.body_text or ""
        if parsed.body_html:
            # HTMLタグを除去してテキスト抽出
            body_text += re.sub(r'<[^>]+>', ' ', parsed.body_html)

        if self.config.get('detection', {}).get('check_body', True) and body_text:
            score, reasons = self._check_body_keywords(body_text)
            total_score += score
            result.reasons.extend(reasons)

        # URLチェック
        if self.config.get('detection', {}).get('check_urls', True) and parsed.urls:
            score, reasons, suspicious_urls = self._check_urls(parsed.urls)
            total_score += score
            result.reasons.extend(reasons)
            result.suspicious_urls.extend(suspicious_urls)

        # 送信者チェック
        if self.config.get('detection', {}).get('check_sender', True):
            score, reasons = self._check_sender(parsed)
            total_score += score
            result.reasons.extend(reasons)

        # [追加] HTMLパターンチェック
        if self.config.get('detection', {}).get('check_html_patterns', True) and parsed.body_html:
            score, reasons = self._check_html_patterns(parsed.body_html)
            total_score += score
            result.reasons.extend(reasons)

        # [追加] スコアのキャップ（最大200点）
        max_score = self.scoring.get('max_score', 200)
        total_score = min(total_score, max_score)

        # スコアからリスクレベルを決定
        result.score = total_score
        threshold_danger = self.scoring.get('threshold_danger', 60)
        threshold_warning = self.scoring.get('threshold_warning', 30)

        if total_score >= threshold_danger:
            result.risk_level = "danger"
        elif total_score >= threshold_warning:
            result.risk_level = "warning"
        else:
            result.risk_level = "safe"

        logger.info(
            f"検知完了: [{result.risk_level.upper()}] スコア={total_score} "
            f"件名=\"{parsed.subject[:50]}\" 送信者={parsed.from_address}"
        )

        return result
