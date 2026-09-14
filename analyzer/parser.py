# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/parser.py

転送されてきた報告メールを、外側（報告そのもの）と
内側（元の不審メール）に分離する。

この分離が解析エンジンの土台。ここを間違えると、
判定対象が「転送してきたメールサービス」になってしまい、
常に spf=pass となって判定が無意味になる。

構造:
  ┌─ 外側：報告者 → 解析システムへの転送メール ─────────┐
  │  From: 報告者                                        │
  │  Authentication-Results: <自前MTA>; spf=pass         │ ← 報告者の正当性
  │                                                       │
  │  ┌─ 内側：元の不審メール（message/rfc822）────────┐ │
  │  │  From: it-support@example.ac.jp  ← 詐称        │ │
  │  │  Authentication-Results: mx.google.com;        │ │ ← ★判定対象
  │  │                          dmarc=fail            │ │
  │  └────────────────────────────────────────────────┘ │
  └───────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import email
import logging
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

from config import cfg

log = logging.getLogger(__name__)

# 自前の受信MTAが Authentication-Results に付与する AuthservID。
# 通常は受信サーバーのホスト名（Postfix の myhostname）。
#
# 設定は config.yaml の mta.authserv_id
# （環境変数 PHISH_MTA_AUTHSERV_ID で上書き可）。
#
# 未設定だと「転送してきたサーバーの検証結果」を
# 「元メールの検証結果」と誤認し、判定が静かに壊れる。
# 具体的には、転送は常に Gmail 等から来るため毎回 spf=pass となり、
# 元メールの認証失敗を検出できなくなる。
OWN_AUTHSERV_ID = cfg.get("mta.authserv_id", "")

if not OWN_AUTHSERV_ID:
    log.warning(
        "mta.authserv_id が未設定です。自前MTAの認証結果を除外できず、"
        "判定が誤る可能性があります"
    )


@dataclass
class ParsedReport:
    """報告メールを分離した結果"""
    # 外側：転送メールそのもの
    outer: EmailMessage
    # 内側：元の不審メール。inline の場合は outer と同じものが入る
    inner: EmailMessage
    # "attached" = 添付転送（ヘッダー完全体あり）
    # "inline"   = 通常転送（ヘッダー欠落）
    mode: str
    # 報告者のメールアドレス（外側の From）
    reporter: str = ""
    # 外側に付いた自前の検証結果（報告者のなりすまし検出用）
    outer_auth: str = ""
    # 解析中に気づいた問題点
    warnings: list[str] = field(default_factory=list)


def parse_report(raw: bytes) -> ParsedReport:
    """
    報告メールの生バイト列を受け取り、外側と内側に分離する。

    policy.default を指定すると、MIMEエンコードされたヘッダー
    （=?utf-8?B?...?= 形式の日本語件名など）が自動でデコードされる。
    policy.compat32（既定）だとエンコードされたままになるので注意。
    """
    outer = email.message_from_bytes(raw, policy=policy.default)

    warnings: list[str] = []

    # 報告者は外側の From。転送元のメールサービスから来るので
    # 通常は信用できるが、外側の認証結果で裏を取る（check_reporter で使う）
    _, reporter = parseaddr(str(outer.get("From", "")))

    # 自前のMTAが付けた Authentication-Results を取り出す。
    # 複数ある場合があるので、AuthservID が自分のものだけを拾う
    outer_auth = ""
    if OWN_AUTHSERV_ID:
        for value in outer.get_all("Authentication-Results", []):
            v = str(value)
            if v.strip().startswith(OWN_AUTHSERV_ID):
                outer_auth = v
                break

    # --- 内側の元メールを探す ---
    inner = _extract_original(outer)

    if inner is not None:
        mode = "attached"
    else:
        # 通常転送。元メールのヘッダーは本文に埋め込まれているだけで、
        # 構造化されたヘッダーとしては取得できない。
        # 外側をそのまま解析対象とし、確度を下げて扱う
        mode = "inline"
        inner = outer
        warnings.append(
            "添付として転送されていないため、元メールのヘッダーが取得できません。"
            "URL と本文のみで判定しています。"
        )

    return ParsedReport(
        outer=outer,
        inner=inner,
        mode=mode,
        reporter=reporter,
        outer_auth=outer_auth,
        warnings=warnings,
    )


def _extract_original(msg: EmailMessage) -> EmailMessage | None:
    """
    message/rfc822 パートを探して、入れ子になった元メールを取り出す。

    メールクライアントの「添付ファイルとして転送」は、元メールを
    message/rfc822 として添付する。walk() で全パートを巡回して探す。

    複数添付されている場合（複数のメールをまとめて転送した場合）は
    最初の1通のみを対象とする。
    """
    for part in msg.walk():
        if part.get_content_type() != "message/rfc822":
            continue

        # message/rfc822 の payload は、内側の Message を1つ含むリスト。
        # get_payload() がリストを返すので [0] で取り出す
        payload = part.get_payload()

        if isinstance(payload, list) and payload:
            return payload[0]

        # 稀に get_payload() が文字列を返す実装差異がある。
        # その場合は再パースして Message に戻す
        if isinstance(payload, (str, bytes)):
            data = payload.encode() if isinstance(payload, str) else payload
            try:
                return email.message_from_bytes(data, policy=policy.default)
            except Exception as e:
                log.warning("message/rfc822 の再パースに失敗: %s", e)

    return None


# ----------------------------------------------------------------------
# ヘッダー取り出しのヘルパー
# ----------------------------------------------------------------------

def domain_of(addr: str) -> str:
    """メールアドレスからドメイン部分を取り出す。小文字化して比較のブレを防ぐ"""
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower().strip().rstrip(".")


def get_addr(msg: EmailMessage, header: str) -> tuple[str, str]:
    """
    指定ヘッダーを (表示名, アドレス) に分解する。

    詐称メールは「表示名だけ実在組織、アドレスは無関係」というパターンが
    極めて多いため、この2つを必ず分けて扱う。
    """
    raw = msg.get(header)
    if raw is None:
        return ("", "")
    return parseaddr(str(raw))


def get_all_addrs(msg: EmailMessage, header: str) -> list[tuple[str, str]]:
    """To や Cc のように複数アドレスを含むヘッダーを全て取り出す"""
    values = msg.get_all(header, [])
    if not values:
        return []
    return getaddresses([str(v) for v in values])


def get_auth_results(msg: EmailMessage) -> list[str]:
    """
    Authentication-Results ヘッダーを全て取り出す。

    内側のメールでは、報告者の受信サーバー（Gmail なら mx.google.com）が
    付けたものが入っている。これが判定の最重要材料。
    """
    return [str(v) for v in msg.get_all("Authentication-Results", [])]


def get_arc_auth_results(msg: EmailMessage) -> list[str]:
    """
    ARC-Authentication-Results を取り出す。

    メーリングリストなどの中継で SPF が壊れた場合、
    中継前の認証結果がここに保存されていることがある。
    Authentication-Results が無いときの代替材料になる。
    """
    return [str(v) for v in msg.get_all("ARC-Authentication-Results", [])]


def get_received_chain(msg: EmailMessage) -> list[str]:
    """
    Received ヘッダーを配送順（古い順）で返す。

    メールヘッダーでは新しい Received が上に積まれるため、
    リストを逆順にすると実際の配送順になる。
    """
    received = [str(v) for v in msg.get_all("Received", [])]
    return list(reversed(received))
