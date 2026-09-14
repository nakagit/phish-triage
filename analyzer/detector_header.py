# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/detector_header.py

ヘッダー系シグナル(H01〜H14)の検出。
H09/H15 は外部照会が必要なため enrich.py が担当する。

方針:
  - 判定対象は「内側の元メール」のみ。外側(転送メール)のヘッダーは
    報告者のなりすまし検出にしか使わない。
  - ドメイン比較は必ず組織ドメイン(eTLD+1)単位で行う。
    example.com と mail.example.com を別物として扱うと誤検知になる。
  - 外部通信は一切しない。DNSもWHOISも引かない。
    この層は「手元の情報だけで確実に言えること」に徹する。
"""
from __future__ import annotations

import ipaddress
import logging
import re
from email.message import EmailMessage

import tldextract

from config import cfg
from parser import (
    OWN_AUTHSERV_ID,
    ParsedReport,
    domain_of,
    get_addr,
    get_arc_auth_results,
    get_auth_results,
    get_received_chain,
)
from scoring import Signal

log = logging.getLogger(__name__)

# OWN_AUTHSERV_ID は parser 側で定義し、ここでは取り込むだけにする。
# 同じ値を2箇所で定義すると、片方だけ変更した際に判定が静かに壊れる。

# tldextract のキャッシュ置き場。
# 既定では ~/.cache を使うが、systemd の ProtectHome=read-only 下では
# 書き込めず [Errno 30] Read-only file system で解析が失敗する。
# 書き込み可能な場所を明示し、service の ReadWritePaths にも追加すること
_TLD_CACHE_DIR = cfg.get("cache.tldextract")

# suffix_list_urls=() で内蔵スナップショットのみを使い、外部通信を止める。
# 解析サーバーから不用意に外へ出ないようにするための措置
_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=_TLD_CACHE_DIR,
)

# Authentication-Results 内の "spf=pass" のような記述を取り出す
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

# DKIM署名者のドメインを取り出す。header.i=@example.com または header.d=example.com。
# header.s=(セレクタ) を誤って拾わないよう、i と d だけを対象にする
_DKIM_SIGNER_RE = re.compile(r"header\.(?:i=@?|d=)([\w.\-]+)", re.IGNORECASE)

# Received ヘッダーから接続元IPを取り出す。
# "from host (host [1.2.3.4])" のような形式の角括弧内を狙う
_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")

# フリーメールのドメイン。H07(表示名詐称)、H13の判定に使う
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.co.jp", "yahoo.com",
    "outlook.com", "outlook.jp", "hotmail.com", "hotmail.co.jp",
    "live.jp", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "protonmail.com", "proton.me", "gmx.com", "gmx.net",
    "zoho.com", "yandex.com", "yandex.ru", "mail.ru",
    "qq.com", "163.com", "126.com", "sina.com",
    "excite.co.jp", "nifty.com", "ocn.ne.jp", "biglobe.ne.jp",
    "so-net.ne.jp", "au.com", "ezweb.ne.jp", "docomo.ne.jp", "softbank.ne.jp",
}

# 大量配信サービスのドメイン。
# これ自体は正規のサービスだが、フリーメールのFromと組み合わさると矛盾する。
# gmail.com が Amazon SES から送信されることはあり得ない
BULK_SENDER_DOMAINS = {
    "amazonses.com", "sendgrid.net", "mailgun.org", "mailgun.net",
    "mailchimp.com", "mcsv.net", "rsgsv.net",
    "sparkpostmail.com", "mandrillapp.com", "postmarkapp.com",
    "sendinblue.com", "brevo.com", "mailjet.com", "elasticemail.com",
    "constantcontact.com", "klaviyomail.com", "bmsend.com",
}

# 表示名詐称(H07)の判定に使う、組織を示唆する語。
# フリーメールなのにこれらを名乗るのは詐称の典型
ORG_HINT_WORDS = [
    "株式会社", "有限会社", "合同会社", "銀行", "信用金庫", "カード",
    "サポート", "サービス", "事務局", "センター", "管理者", "運営",
    "部", "課", "室", "大学", "学部", "公式", "カスタマー",
    "Support", "Admin", "Service", "Team", "Security", "Billing",
    "Inc", "Corp", "Ltd", "Bank", "Official", "Help", "Desk",
]


def org_domain(domain: str) -> str:
    """
    ドメインから組織ドメイン(eTLD+1)を取り出す。

    tldextract は Public Suffix List を内蔵しているため、
    ac.jp や co.jp のような多段TLDを正しく扱える。
    単純に「末尾2要素」で切ると example.ac.jp が ac.jp になってしまい、
    自組織判定が完全に壊れる。

    例:
      mail.example.com   -> example.com
      imc.example.ac.jp  -> example.ac.jp
      evil.co.uk         -> evil.co.uk
    """
    if not domain:
        return ""
    try:
        ext = _extract(domain.lower().strip().rstrip("."))
    except Exception as e:
        # キャッシュディレクトリの権限問題などで失敗し得る。
        # 解析全体を止めないよう、入力をそのまま返して続行する
        log.warning("tldextract に失敗しました (%s): %s", domain, e)
        return domain.lower().strip().rstrip(".")

    if not ext.domain or not ext.suffix:
        return domain.lower().strip().rstrip(".")
    return f"{ext.domain}.{ext.suffix}"


def _own_filtered(values: list[str]) -> list[str]:
    """
    自前のMTAが付けたヘッダーを除外する。

    OWN_AUTHSERV_ID が未設定だと除外が効かず、
    転送してきたサーバーの検証結果を元メールのものと誤認する。
    その場合は全件を返すが、parser 側で起動時に警告を出している。
    """
    if not OWN_AUTHSERV_ID:
        return values
    return [v for v in values if OWN_AUTHSERV_ID not in v]


def parse_auth_results(values: list[str]) -> dict[str, str]:
    """
    Authentication-Results の文字列群から spf/dkim/dmarc の結果を取り出す。

    同じ種別が複数回出現する場合(複数の署名を検証した場合など)は、
    最初に pass があれば pass を優先する。
    1つでも正当な署名が通っていれば、そのメールは詐称ではないため。
    """
    results: dict[str, str] = {}

    for value in values:
        for method, verdict in _AUTH_RE.findall(value):
            method = method.lower()
            verdict = verdict.lower()
            # 既に pass が記録されている項目は上書きしない
            if results.get(method) == "pass":
                continue
            results[method] = verdict

    return results


def get_effective_auth(inner: EmailMessage) -> tuple[dict[str, str], list[str], str]:
    """
    判定に使う認証結果を決定する。

    優先順位:
      1. Authentication-Results (報告者の受信サーバーが付けたもの)
      2. ARC-Authentication-Results (中継前の結果が残っている場合がある)
      3. なし

    戻り値: (認証結果の辞書, 元のヘッダー文字列群, 情報源のラベル)
    """
    ar = _own_filtered(get_auth_results(inner))
    if ar:
        return parse_auth_results(ar), ar, "Authentication-Results"

    arc = _own_filtered(get_arc_auth_results(inner))
    if arc:
        return parse_auth_results(arc), arc, "ARC-Authentication-Results"

    return {}, [], ""


def extract_sender_ip(inner: EmailMessage) -> str | None:
    """
    元メールの最初の送信元IP(最も外側のホップ)を取り出す。

    Received は新しいものが上に積まれるため、get_received_chain() で
    逆順にしたリストの先頭が「最初に受け取ったサーバー」になる。

    プライベートIPは社内MTA経由を意味するのでスキップし、
    最初に見つかったグローバルIPを返す。
    """
    for line in get_received_chain(inner):
        for candidate in _IP_RE.findall(line):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                return str(ip)
    return None


def extract_dkim_signer(auth_values: list[str]) -> str:
    """
    DKIM署名者のドメインを取り出す。

    正規のメール配信代行では、From のドメインで署名するのが通常なので、
    ここが From と異なる場合は「別人の署名」を意味する。

    dkim=pass が含まれるヘッダーからのみ署名者を取る。
    fail した署名の署名者を見ても意味がない。
    """
    for value in auth_values:
        if "dkim=pass" not in value.lower():
            continue
        m = _DKIM_SIGNER_RE.search(value)
        if m:
            return m.group(1)
    return ""


def detect(report: ParsedReport, org_domains: list[str]) -> list[Signal]:
    """
    ヘッダー系のシグナルを検出する。

    report      : parser.parse_report() の結果
    org_domains : 自組織ドメインのリスト(scoring.yaml から渡す)
    """
    inner = report.inner
    signals: list[Signal] = []

    # 自組織ドメインも組織ドメイン単位に正規化しておく
    org_set = {org_domain(d) for d in org_domains}

    # ---- アドレス系の取り出し ----
    from_name, from_addr = get_addr(inner, "From")
    _, return_path = get_addr(inner, "Return-Path")
    _, reply_to = get_addr(inner, "Reply-To")

    from_domain = domain_of(from_addr)
    from_org = org_domain(from_domain)
    rp_domain = domain_of(return_path)
    rp_org = org_domain(rp_domain)
    rt_org = org_domain(domain_of(reply_to))

    # ================================================================
    # 認証結果 (H01〜H04, H11, H12, H14)
    # ================================================================
    auth, auth_values, source = get_effective_auth(inner)

    if not auth:
        # 認証結果が一切ない。古いMTA経由の可能性もあるため配点は低い
        signals.append(Signal("H11", "認証結果ヘッダーが存在しません"))
    else:
        dmarc = auth.get("dmarc", "")
        spf = auth.get("spf", "")
        dkim = auth.get("dkim", "")

        # ---- H01: DMARC失敗 ----
        # 送信ドメイン詐称のほぼ確定証拠。最高配点
        if dmarc == "fail":
            signals.append(Signal("H01", f"dmarc=fail ({source})"))

        # ---- H02/H03/H14: SPF ----
        if spf == "fail":
            signals.append(Signal("H02", f"spf=fail ({source})"))
        elif spf == "softfail":
            signals.append(Signal("H03", f"spf=softfail ({source})"))
        elif spf == "none":
            # SPFレコード未設定。正規のドメインならまず設定されている
            signals.append(Signal("H14", f"spf=none ({source})"))

        # ---- H04: DKIM失敗 ----
        if dkim == "fail":
            signals.append(Signal("H04", f"dkim=fail ({source})"))

        # ---- H12: 署名ドメインと From のアライメント不整合 ----
        # dkim=pass でも署名者が別組織なら「別人の署名」。
        # 攻撃者が正規の配信サービスを借りて From だけ偽装する手口を捉える
        if dkim == "pass":
            signer = extract_dkim_signer(auth_values)
            signer_org = org_domain(signer)
            if signer_org and from_org and signer_org != from_org:
                signals.append(
                    Signal("H12", f"署名={signer_org} / From={from_org}")
                )

        # ---- 減点: 自組織の正規通知 ----
        # DMARC pass は「送信ドメインが本物である」ことの強い証拠
        if dmarc == "pass" and from_org in org_set:
            signals.append(
                Signal("S02", f"自組織ドメイン({from_org})から dmarc=pass")
            )

    # ================================================================
    # H05: From と Return-Path のドメイン不一致
    # ================================================================
    # 重要: 組織ドメイン単位で比較する。
    # example.com と mail.example.com を不一致とすると、
    # 大量配信サービスを使う正規企業のメールが軒並み誤検知になる
    if return_path and from_org and rp_org and from_org != rp_org:
        # DKIM が pass していれば送信自体は正当なので立てない。
        # 転送サービス経由でエンベロープが変わるのは正常な動作
        if auth.get("dkim") != "pass":
            signals.append(
                Signal("H05", f"From={from_org} / Return-Path={rp_org}")
            )

    # ================================================================
    # H06: Reply-To が From と別ドメイン (BECの典型)
    # ================================================================
    if reply_to and from_org and rt_org and from_org != rt_org:
        signals.append(Signal("H06", f"From={from_org} / Reply-To={reply_to}"))

    # ================================================================
    # H07: 表示名詐称 (実在組織名 + フリーメール)
    # ================================================================
    if from_name and from_domain in FREEMAIL_DOMAINS:
        hints = ORG_HINT_WORDS + [d.split(".")[0] for d in org_set]
        matched = [h for h in hints if h.lower() in from_name.lower()]
        if matched:
            signals.append(
                Signal("H07", f"表示名='{from_name}' / アドレス={from_addr}")
            )

    # ================================================================
    # H08: 自組織ドメインの詐称 (外部からの着信)
    # ================================================================
    if from_org in org_set:
        # From が自組織なのに認証が通っていない = 詐称の可能性が高い
        dmarc_ok = auth.get("dmarc") == "pass"
        dkim_ok = auth.get("dkim") == "pass"

        if not dmarc_ok and not dkim_ok:
            sender_ip = extract_sender_ip(inner)
            detail = f"From={from_addr}"
            if sender_ip:
                detail += f" / 送信元IP={sender_ip}"
            signals.append(Signal("H08", detail))

    # ================================================================
    # H13: フリーメール From + 大量配信基盤
    # ================================================================
    # gmail.com が Amazon SES や SendGrid から送られることはあり得ない。
    # 攻撃者が正規インフラを借りてスパムフィルタを回避する手口
    if from_domain in FREEMAIL_DOMAINS and rp_org in BULK_SENDER_DOMAINS:
        signals.append(Signal("H13", f"From={from_domain} / 送信基盤={rp_org}"))

    # ================================================================
    # H10: Received チェーンの矛盾
    # ================================================================
    if _has_broken_chain(inner):
        signals.append(Signal("H10", "Received の時刻が逆行しています"))

    return signals


def _has_broken_chain(inner: EmailMessage) -> bool:
    """
    Received チェーンの時刻が配送順と矛盾していないか確認する。

    正常なメールでは、配送が進むほど時刻が新しくなる。
    逆行している場合、ヘッダーが偽造された可能性がある。

    注意: サーバー間の時計ずれで数分程度の逆行は普通に起きるため、
    明確に矛盾している場合(5分以上の逆行)のみ検出する。
    """
    from email.utils import parsedate_to_datetime

    timestamps = []
    for line in get_received_chain(inner):
        # Received の末尾に "; Mon, 1 Sep 2026 10:14:00 +0900" 形式で時刻が入る
        if ";" not in line:
            continue
        date_part = line.rsplit(";", 1)[-1].strip()
        try:
            dt = parsedate_to_datetime(date_part)
        except Exception:
            continue
        # タイムゾーンなしの日時が混ざると比較で例外が出るので除外する
        if dt.tzinfo is None:
            continue
        timestamps.append(dt)

    if len(timestamps) < 2:
        return False

    for prev, curr in zip(timestamps, timestamps[1:]):
        # 5分(300秒)以上の逆行は時計ずれでは説明できない
        if (curr - prev).total_seconds() < -300:
            return True

    return False


def check_reporter(report: ParsedReport) -> list[str]:
    """
    報告者自身のなりすましを確認する。

    外側(転送メール)の認証結果を見る。ここが fail している場合、
    「社員を騙った偽の報告」の可能性があるため、
    判定スコアとは別の警告として扱う。
    """
    warnings: list[str] = []

    if not report.outer_auth:
        # ローカル投函などでは付かないので、何も言わない
        return warnings

    auth = parse_auth_results([report.outer_auth])

    if auth.get("spf") in ("fail", "softfail"):
        warnings.append(
            f"報告メール自体の SPF が {auth['spf']} です"
            f"（報告者: {report.reporter}）。なりすましの可能性があります。"
        )

    return warnings
