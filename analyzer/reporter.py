# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/reporter.py

判定結果を日本語のレポートに整形する。

2種類を生成する:
  - 報告者向け: 非技術者が読んで行動できる文面。scoring.yaml の
    description を使う。判定別に構造を変え、正常時は必ず謝意を入れる。
  - 担当者向け: シグナル一覧・配点内訳・IOC。label を使う。

設計上の原則:
  - レポート内のURLは必ず defang する。スキームだけでなくホスト部の
    ドットも置換しないと、メールクライアントがリンク化してしまう。
  - 正常判定で「安心してください」と書かない。認証が通っているだけで
    安全の保証にはならず、システムがお墨付きを与える形になるのは危険。
  - inline モード(通常転送)では確度の低さを明記し、判定を鵜呑みにさせない。
  - 断定の強さを判定に応じて変える。「疑わしい」で「危険です」と書くと、
    誤検知時に報告者の信頼を失う。
  - プレーンテキストメールなので Markdown 記法を使わない。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from config import cfg
from detector_attach import AttachAnalysis
from detector_url import UrlAnalysis
from parser import ParsedReport, domain_of, get_addr
from scoring import Result, VERDICT_JA

JST = timezone(timedelta(hours=9))

# レポート内で案内する問い合わせ先。
# 組織ごとに異なるため config.yaml の notify.contact_name で設定する
CONTACT_NAME = cfg.get("notify.contact_name")

# カテゴリの日本語表示（担当者向けレポートの章立てに使う）
CATEGORY_JA: dict[str, str] = {
    "header": "送信元・認証",
    "url": "リンク",
    "attachment": "添付ファイル",
    "context": "文面",
    "safe": "正常と判断した要素",
}

# defang 用。hxxp(s):// の直後のホスト部分を捉える
_DEFANG_HOST_RE = re.compile(r"(hxxps?://)([^/\s]+)")


def defang(text: str) -> str:
    """
    テキスト中のURLを無害化する。

    スキームを hxxp に変えるだけでは不十分。
    メールクライアントは "example.com/path" 形式もリンクとして
    認識するため、ホスト部のドットも [.] に置換する。
    パス以降のドットはリンク化の起点にならないので対象外。
    """
    text = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return _DEFANG_HOST_RE.sub(
        lambda m: m.group(1) + m.group(2).replace(".", "[.]"),
        text,
    )


def defang_domain(domain: str) -> str:
    """ドメイン名やメールアドレスを無害化する"""
    return domain.replace(".", "[.]")


@dataclass
class Report:
    """生成されたレポート一式"""
    subject_user: str = ""      # 報告者へ送るメールの件名
    body_user: str = ""         # 報告者向け本文（プレーンテキスト）
    subject_soc: str = ""       # 担当者へ送るメールの件名
    body_soc: str = ""          # 担当者向け本文（プレーンテキスト）
    iocs: dict = field(default_factory=dict)   # OpenCTI 投入用


# ----------------------------------------------------------------------
# 報告者向けレポート
# ----------------------------------------------------------------------

# 判定ごとの見出しと導入文。
# 断定の強さを判定に応じて変える。「疑わしい」で「危険です」と書くと、
# 誤検知だったときに報告者の信頼を失う
_USER_INTRO: dict[str, tuple[str, str]] = {
    "malicious": (
        "【危険】ご報告いただいたメールについて",
        "ご報告ありがとうございました。\n"
        "解析の結果、このメールは【危険】と判定されました。\n"
        "以下の対応をお願いいたします。",
    ),
    "suspicious": (
        "【要注意】ご報告いただいたメールについて",
        "ご報告ありがとうございました。\n"
        "解析の結果、このメールには不審な点が見つかりました。\n"
        "現在、担当者が詳細を確認しています。\n"
        "念のため、リンクを開いたり添付ファイルを実行したりせず、\n"
        "そのままお待ちください。",
    ),
    "unknown": (
        "【確認中】ご報告いただいたメールについて",
        "ご報告ありがとうございました。\n"
        "自動解析では明確な判断ができませんでした。\n"
        "担当者が内容を確認のうえ、改めてご連絡いたします。\n"
        "それまでは、リンクや添付ファイルを開かずにお待ちください。",
    ),
    "benign": (
        "【解析結果】ご報告いただいたメールについて",
        "ご報告ありがとうございました。\n"
        "解析の結果、このメールから明らかな危険性は検出されませんでした。\n"
        "送信元の認証は正常で、添付ファイルやリンクにも\n"
        "既知の問題は見つかっていません。",
    ),
}

# 判定ごとの行動指示。悪性・疑わしいの場合のみ具体的な手順を示す
_USER_ACTIONS: dict[str, list[str]] = {
    "malicious": [
        "メール内のリンクを開かないでください。",
        "添付ファイルを開かないでください。",
        "このメールに返信しないでください。",
        f"すでにリンクを開いた、添付を実行した、"
        f"ID・パスワードを入力したという場合は、\n"
        f"   至急、{CONTACT_NAME}へご連絡ください。",
        "その後、メールを削除していただいて構いません。",
    ],
    "suspicious": [
        "リンクや添付ファイルを開かないでください。",
        "このメールに返信しないでください。",
        "担当者からの連絡をお待ちください。",
    ],
}

# 正常判定時に添える文。
#
# 「安心してご利用ください」とは書かない。認証が通っているだけであり、
# 安全の保証にはならないため。万一それが巧妙な攻撃だった場合、
# システムがお墨付きを与えたことになる。
# 同時に「報告しても素っ気ない」と感じさせると報告率が落ちるので、
# 謝意と継続依頼は必ず入れる
_BENIGN_CLOSING = (
    "ただし、この判定は自動解析によるものであり、\n"
    "安全を保証するものではありません。\n"
    "心当たりのない依頼や、ID・パスワードの入力を求める内容であれば、\n"
    "認証結果にかかわらず応じないでください。\n"
    "\n"
    f"少しでも不安を感じられた場合は、遠慮なく{CONTACT_NAME}へ\n"
    "お問い合わせください。\n"
    "今後も不審なメールを見かけた際は、ぜひご報告をお願いいたします。"
)


def build_user_report(
    report: ParsedReport,
    result: Result,
    url: UrlAnalysis,
    attach: AttachAnalysis,
) -> tuple[str, str]:
    """報告者向けのレポートを生成する"""
    subject_tpl, intro = _USER_INTRO[result.verdict]

    inner_subject = str(report.inner.get("Subject") or "(件名なし)")
    _, from_addr = get_addr(report.inner, "From")

    lines: list[str] = [intro, ""]

    # ---- 対象メールの特定情報 ----
    # どのメールについての回答かを明確にする。
    # 複数報告した場合に取り違えないため
    lines.append("─" * 40)
    lines.append(f"件名　: {inner_subject}")
    lines.append(f"差出人: {defang_domain(from_addr)}")
    lines.append("─" * 40)
    lines.append("")

    # ---- 確認された問題（悪性・疑わしいのみ）----
    if result.verdict in ("malicious", "suspicious"):
        # 危険度の高い順に並べ、重要なものから読ませる。
        # 減点要素(safe)は報告者向けには出さない
        problems = sorted(
            [s for s in result.signals if s.category != "safe"],
            key=lambda s: s.score,
            reverse=True,
        )
        if problems:
            lines.append("■ 確認された問題")
            for s in problems:
                lines.append(f"・{s.description}")
            lines.append("")

    # ---- 即時確定の理由 ----
    if result.is_instant:
        lines.append("■ 判定の決め手")
        lines.append(f"・{result.instant_reason}")
        lines.append("")

    # ---- 確認した内容（正常判定のみ）----
    # 何を見たのかを伝えないと「本当に調べたのか」という不信につながる。
    # 報告してよかったと感じてもらうために必要
    if result.verdict == "benign":
        lines.append("■ 確認した内容")
        lines.append("・送信元の認証（このメールが差出人本人から送られたか）")
        if url.urls:
            lines.append(f"・メール内のリンク {len(url.urls)} 件")
        if attach.attachments:
            lines.append(f"・添付ファイル {len(attach.attachments)} 件")
        lines.append("")

    # ---- 行動指示 ----
    actions = _USER_ACTIONS.get(result.verdict)
    if actions:
        lines.append("■ お願いしたい対応")
        for i, action in enumerate(actions, 1):
            lines.append(f"{i}. {action}")
        lines.append("")

    # ---- 添付ファイルの警告 ----
    if attach.attachments and result.verdict in ("malicious", "suspicious"):
        lines.append("■ 注意が必要な添付ファイル")
        for a in attach.attachments:
            lines.append(f"・{a.filename}")
        lines.append("")

    # ---- 確度の注記 ----
    # 通常転送の場合、判定材料が不足していることを必ず伝える。
    # 「安全」と誤解させないため、benign でも出す
    if report.mode == "inline":
        lines.append("■ 判定の確度について")
        lines.append(
            "このメールは通常の転送で報告されたため、\n"
            "送信元を検証するための情報が失われています。\n"
            "そのため、判定の確度は限定的です。\n"
            "より正確な判定のためには、対象メールを開かずに\n"
            "チェックを入れ、「添付ファイルとして転送」でご報告いただけると\n"
            "助かります。"
        )
        lines.append("")

    # ---- 締め ----
    if result.verdict == "benign":
        lines.append(_BENIGN_CLOSING)
    else:
        lines.append(
            f"ご不明な点がありましたら、{CONTACT_NAME}まで\n"
            "お問い合わせください。"
        )

    lines.append("")
    lines.append("─" * 40)
    lines.append("このメールは不審メール解析システムから自動送信されています。")

    return subject_tpl, "\n".join(lines)


# ----------------------------------------------------------------------
# 担当者向けレポート
# ----------------------------------------------------------------------

def build_soc_report(
    report: ParsedReport,
    result: Result,
    url: UrlAnalysis,
    attach: AttachAnalysis,
    reporter_warnings: list[str],
) -> tuple[str, str]:
    """担当者向けのレポートを生成する"""
    from detector_header import extract_sender_ip

    inner_subject = str(report.inner.get("Subject") or "(件名なし)")
    from_name, from_addr = get_addr(report.inner, "From")
    _, return_path = get_addr(report.inner, "Return-Path")
    _, reply_to = get_addr(report.inner, "Reply-To")

    verdict_ja = VERDICT_JA[result.verdict]
    score_str = "即時確定" if result.is_instant else f"{result.score}点"

    subject = f"[{verdict_ja}/{score_str}] {inner_subject[:40]}"

    lines: list[str] = []

    # ---- サマリ ----
    # 担当者が最初の数行で優先度を判断できるようにする
    lines.append("=" * 50)
    lines.append(f"判定　: {verdict_ja}（{score_str}）")
    lines.append(f"確度　: {result.confidence}")
    lines.append(f"報告者: {report.reporter}")
    lines.append(f"解析　: {datetime.now(JST).strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 50)
    lines.append("")

    if result.is_instant:
        lines.append(f"【即時確定】{result.instant_reason}")
        lines.append("")

    # ---- 報告者のなりすまし警告 ----
    # 判定スコアとは別枠。報告そのものが偽の可能性を担当者に伝える
    if reporter_warnings:
        lines.append("【報告者に関する警告】")
        for w in reporter_warnings:
            lines.append(f"  {w}")
        lines.append("")

    # ---- 元メールのヘッダー ----
    lines.append("■ 元メール")
    lines.append(f"  件名　　　　: {inner_subject}")
    # 表示名が空のときに余分な空白が入らないようにする
    if from_name:
        lines.append(f"  From　　　　: {from_name} <{defang_domain(from_addr)}>")
    else:
        lines.append(f"  From　　　　: {defang_domain(from_addr)}")
    if return_path:
        lines.append(f"  Return-Path : {defang_domain(return_path)}")
    if reply_to:
        lines.append(f"  Reply-To　　: {defang_domain(reply_to)}")

    sender_ip = extract_sender_ip(report.inner)
    if sender_ip:
        lines.append(f"  送信元IP　　: {defang_domain(sender_ip)}")

    lines.append(f"  転送方式　　: {report.mode}")
    lines.append("")

    # ---- 検出シグナル（カテゴリ別）----
    lines.append(f"■ 検出シグナル（{len(result.signals)}件）")
    if not result.signals:
        lines.append("  （なし）")
    else:
        for cat in ("header", "url", "attachment", "context", "safe"):
            items = result.signals_by_category(cat)
            if not items:
                continue
            lines.append(f"  [{CATEGORY_JA[cat]}]")
            # 配点の大きい順。減点は符号順で末尾に来る
            for s in sorted(items, key=lambda x: x.score, reverse=True):
                lines.append(f"    {s.rule_id} ({s.score:+d}) {s.label}")
                if s.detail:
                    lines.append(f"        {defang(s.detail)}")
    lines.append("")

    # ---- 抽出URL ----
    if url.urls:
        lines.append(f"■ 抽出URL（{len(url.urls)}件 / "
                     f"{len(url.unique_hosts)}ホスト）")
        for u in url.urls[:15]:
            lines.append(f"  {defang(u.url)}")
            if u.anchor_text:
                lines.append(f"      表示テキスト: {u.anchor_text[:60]}")
        if len(url.urls) > 15:
            lines.append(f"  ...他 {len(url.urls) - 15} 件")
        lines.append("")

    # ---- 添付ファイル ----
    if attach.attachments:
        lines.append(f"■ 添付ファイル（{len(attach.attachments)}件）")
        for a in attach.attachments:
            lines.append(f"  {a.filename}")
            lines.append(f"      MIME　: {a.content_type} "
                         f"/ 実体: {a.detected_mime or '不明'}")
            lines.append(f"      サイズ: {a.size:,} バイト")
            # VirusTotal 等での照合に使えるよう完全な形で出す
            lines.append(f"      SHA256: {a.sha256}")
            if a.inner_files:
                lines.append(f"      内容　: {', '.join(a.inner_files[:10])}")
                if len(a.inner_files) > 10:
                    lines.append(f"              ...他 "
                                 f"{len(a.inner_files) - 10} 件")
            if a.error:
                lines.append(f"      エラー: {a.error}")
        lines.append("")

    # ---- 判定の内訳 ----
    if not result.is_instant:
        lines.append("■ スコア内訳")
        lines.append(f"  合計 {result.score}点 "
                     f"（悪性 {result.threshold_malicious}点以上 / "
                     f"疑わしい {result.threshold_suspicious}点以上）")
        lines.append("")

    # ---- パーサの警告 ----
    if report.warnings:
        lines.append("■ 解析上の注意")
        for w in report.warnings:
            lines.append(f"  {w}")
        lines.append("")

    # ---- 未定義ルールの警告 ----
    # detector 側だけ先行実装された場合の取りこぼしを担当者に知らせる
    if result.unknown_rule_ids:
        lines.append("■ 設定不備")
        lines.append(f"  YAML未定義のルールID: "
                     f"{', '.join(result.unknown_rule_ids)}")
        lines.append("")

    lines.append("=" * 50)

    return subject, "\n".join(lines)


# ----------------------------------------------------------------------
# IOC の抽出
# ----------------------------------------------------------------------

def build_iocs(
    report: ParsedReport,
    url: UrlAnalysis,
    attach: AttachAnalysis,
) -> dict:
    """
    OpenCTI へ投入するための IOC を整形する。

    悪性判定されたメールからのみ投入すべきなので、
    呼び出し側で verdict を確認すること。
    ここでは抽出だけ行い、投入の可否は判断しない。

    値は defang しない。機械可読なデータとして扱うため。
    """
    from detector_header import extract_sender_ip

    _, from_addr = get_addr(report.inner, "From")

    return {
        "sender_address": from_addr,
        "sender_domain": domain_of(from_addr),
        "sender_ip": extract_sender_ip(report.inner),
        # 重複を除いたホスト一覧。ドメイン単位の指標として使う
        "domains": url.unique_hosts,
        "urls": [u.url for u in url.urls],
        "file_hashes": [
            {"filename": a.filename, "sha256": a.sha256, "size": a.size}
            for a in attach.attachments if a.sha256
        ],
        "message_id": str(report.inner.get("Message-ID") or ""),
        "subject": str(report.inner.get("Subject") or ""),
    }


# ----------------------------------------------------------------------
# まとめ
# ----------------------------------------------------------------------

def build(
    report: ParsedReport,
    result: Result,
    url: UrlAnalysis,
    attach: AttachAnalysis,
    reporter_warnings: list[str] | None = None,
) -> Report:
    """レポート一式を生成する"""
    reporter_warnings = reporter_warnings or []

    subj_user, body_user = build_user_report(report, result, url, attach)
    subj_soc, body_soc = build_soc_report(
        report, result, url, attach, reporter_warnings
    )

    return Report(
        subject_user=subj_user,
        body_user=body_user,
        subject_soc=subj_soc,
        body_soc=body_soc,
        iocs=build_iocs(report, url, attach),
    )
