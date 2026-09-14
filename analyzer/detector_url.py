# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/detector_url.py

URL系シグナル(U02〜U08)の検出。

方針:
  - 外部通信は一切しない。URLをGETしない、DNSを引かない、WHOISを引かない。
    解析基盤のIPが攻撃者に露見するのを防ぎ、SSRFの踏み台化も避ける。
    通信が必要な U01(既知悪性) と U05(新規ドメイン) は enrich.py に分離する。
  - HTMLパートとテキストパートの両方からURLを抽出する。
    HTMLだけ見ると、テキストパートにしかないURLを取り逃す。
  - ドメイン比較は必ず組織ドメイン(eTLD+1)単位。
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from email.message import EmailMessage
from urllib.parse import urlsplit, unquote

from bs4 import BeautifulSoup

from detector_header import org_domain
from parser import ParsedReport, domain_of, get_addr
from scoring import Signal

log = logging.getLogger(__name__)

# プレーンテキストからURLを拾う正規表現。
#
# 開き括弧 [ ( も必ず除外対象に含めること。含めないと、本文が
#   [https://正規サイト.com](https://攻撃者サイト.com)
# のようなMarkdown形式で書かれていた場合に、開き括弧で止まらず
# 閉じ括弧まで一気に飲み込み、ホスト名の抽出を誤る。
# これは攻撃に悪用され得るため、文字クラスの管理は厳密に行う
_URL_RE = re.compile(
    r"""https?://[^\s<>"'`\[\]\(\)（）「」【】、。,]+""",
    re.IGNORECASE,
)

# URLに認証情報が埋め込まれた形式を検出する。
# http://www.bank.co.jp@evil.example/ のように、@の前を正規サイトに見せかける手口。
# ブラウザは@の後ろへ接続するため、表示と実際の接続先が食い違う
_USERINFO_RE = re.compile(r"^https?://[^/@\s]+@", re.IGNORECASE)

# 短縮URLサービスのドメイン。本当のリンク先が隠される
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "t.ly", "s.id", "v.gd", "x.co", "lnkd.in", "amzn.to",
    "urlz.fr", "tiny.cc", "bl.ink", "shrtco.de", "clck.ru",
}

# オープンリダイレクタとして悪用されやすいクエリパラメータ。
# 正規ドメインを経由して攻撃者のサイトへ飛ばす手口を捉える。
# 値が http(s) で始まる場合のみ該当とし、誤検知を抑える
_REDIRECT_PARAM_RE = re.compile(
    r"[?&](url|redirect|redir|next|target|dest|destination|continue|return|"
    r"returnurl|goto|link|out|to)=(https?(%3A|:))",
    re.IGNORECASE,
)

# ホモグラフ攻撃で使われやすい、ラテン文字に似た他文字のコードブロック。
# 例: キリル文字の а(U+0430) は ラテン a(U+0061) と見分けがつかない
_SUSPICIOUS_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "HEBREW")

# よく詐称される著名ブランドのドメイン。U02の比較対象に加える。
# ここに載せたドメインへのリンクは「正規の参照」として U08 からも除外される
COMMON_BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.co.jp", "amazon.com",
    "rakuten.co.jp", "paypay.ne.jp", "smbc.co.jp", "mufg.jp", "mizuhobank.co.jp",
    "japanpost.jp", "jcb.co.jp", "aeon.co.jp", "docomo.ne.jp",
    "au.com", "softbank.jp", "yamato-hd.co.jp", "sagawa-exp.co.jp",
    "nta.go.jp", "etc-meisai.jp", "jrail.jp", "ana.co.jp", "jal.co.jp",
}


@dataclass
class ExtractedUrl:
    """抽出したURL1件"""
    url: str
    host: str = ""            # ホスト名（小文字化・IDN復号済み）
    org: str = ""             # 組織ドメイン(eTLD+1)
    anchor_text: str = ""     # HTMLのアンカーテキスト（あれば）
    source: str = "text"      # "html" または "text"


@dataclass
class UrlAnalysis:
    """URL解析の結果。シグナルとは別に、抽出結果自体もレポートで使う"""
    urls: list[ExtractedUrl] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)

    @property
    def unique_hosts(self) -> list[str]:
        """重複を除いたホスト名の一覧（出現順を保つ）"""
        seen: list[str] = []
        for u in self.urls:
            if u.host and u.host not in seen:
                seen.append(u.host)
        return seen


# ----------------------------------------------------------------------
# 本文の取り出し
# ----------------------------------------------------------------------

def _get_body_parts(msg: EmailMessage) -> tuple[str, str]:
    """
    メールから text/plain と text/html の本文を取り出す。

    添付ファイル(Content-Disposition: attachment)は除外する。
    添付の中身はこのモジュールでは扱わない(detector_attach.py の担当)。
    """
    text_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        # 添付は本文ではないのでスキップ
        if part.get_content_disposition() == "attachment":
            continue

        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue

        try:
            # decode=True でBase64/quoted-printableを復号する
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            # 文字コードが壊れていても解析は続けたいので errors="replace"
            body = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError) as e:
            # 未知の文字コード指定などは utf-8 で強引に読む
            log.warning("本文のデコードに失敗、utf-8で再試行: %s", e)
            try:
                body = part.get_payload(decode=True).decode("utf-8", errors="replace")
            except Exception:
                continue
        except Exception as e:
            log.warning("本文の取得に失敗: %s", e)
            continue

        if ctype == "text/html":
            html_parts.append(body)
        else:
            text_parts.append(body)

    return "\n".join(text_parts), "\n".join(html_parts)


def _normalize_host(url: str) -> str:
    """
    URLからホスト名を取り出して正規化する。

    IDN(国際化ドメイン名)はPunycode(xn--)で表現されることがあるため、
    可能ならUnicodeに戻してホモグラフ判定にかけられるようにする。
    xn--pple-43d.com → аpple.com（キリル文字入り）が見えるようになる。
    """
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        # ポート番号が不正な場合など。判定不能として空を返す
        return ""

    host = host.lower().rstrip(".")

    if "xn--" in host:
        try:
            host = host.encode("ascii").decode("idna")
        except Exception:
            # 復号できない場合は Punycode のまま扱う
            pass

    return host


def extract_urls(msg: EmailMessage) -> list[ExtractedUrl]:
    """
    メール本文からURLを抽出する。

    HTMLパートからは <a href> とアンカーテキストのペアを取り、
    テキストパートからは正規表現でURLを拾う。
    両方見るのは、HTMLだけだとテキストパートにしかないURLを取り逃すため。
    """
    text_body, html_body = _get_body_parts(msg)
    results: list[ExtractedUrl] = []
    seen: set[tuple[str, str]] = set()

    # ---- HTMLパート ----
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a in soup.find_all("a", href=True):
                href = str(a["href"]).strip()
                if not href.lower().startswith(("http://", "https://")):
                    continue
                # アンカーテキストを取得。改行や連続空白は詰める
                anchor = " ".join(a.get_text(" ", strip=True).split())
                key = (href, anchor)
                if key in seen:
                    continue
                seen.add(key)
                host = _normalize_host(href)
                results.append(ExtractedUrl(
                    url=href, host=host, org=org_domain(host),
                    anchor_text=anchor, source="html",
                ))
        except Exception as e:
            log.warning("HTMLのパースに失敗: %s", e)

    # ---- テキストパート ----
    for m in _URL_RE.finditer(text_body):
        url = m.group(0)
        key = (url, "")
        if key in seen:
            continue
        seen.add(key)
        host = _normalize_host(url)
        results.append(ExtractedUrl(
            url=url, host=host, org=org_domain(host), source="text",
        ))

    return results


# ----------------------------------------------------------------------
# 個別の判定ヘルパー
# ----------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """
    2つの文字列の編集距離を計算する。

    外部ライブラリを使わず標準機能だけで実装する。
    ドメイン名は短いので、この単純な動的計画法で十分速い。
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            # 削除・挿入・置換のうち最小コストを選ぶ
            curr.append(min(
                prev[j] + 1,               # 削除
                curr[j - 1] + 1,           # 挿入
                prev[j - 1] + (ca != cb),  # 置換
            ))
        prev = curr
    return prev[-1]


def _has_mixed_script(host: str) -> tuple[bool, str]:
    """
    ホスト名にラテン文字以外の紛らわしい文字が混ざっていないか判定する。

    完全に非ラテンのドメイン(例: 日本語ドメイン)は正規のものもあるため、
    「ラテン文字と他文字が混在している」場合のみ検出する。
    この混在こそがホモグラフ攻撃の特徴。

    戻り値: (該当するか, 検出した異体字)
    """
    has_latin = False
    suspicious_chars: list[str] = []

    for ch in host:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            # 名前のない文字はスキップ
            continue

        if name.startswith("LATIN"):
            has_latin = True
        elif any(name.startswith(s) for s in _SUSPICIOUS_SCRIPTS):
            suspicious_chars.append(ch)

    if has_latin and suspicious_chars:
        return True, "".join(sorted(set(suspicious_chars)))
    return False, ""


def _is_shortener(host: str) -> bool:
    """短縮URLサービスかどうか"""
    return host in SHORTENER_DOMAINS or org_domain(host) in SHORTENER_DOMAINS


def defang(url: str) -> str:
    """
    URLを無害化する。

    レポートやログに出す際、クライアントが自動リンク化して
    誤クリックを誘発するのを防ぐ。
    """
    return url.replace("http", "hxxp", 1)


# ----------------------------------------------------------------------
# 検出本体
# ----------------------------------------------------------------------

def detect(report: ParsedReport, org_domains: list[str]) -> UrlAnalysis:
    """
    URL系のシグナルを検出する。

    report      : parser.parse_report() の結果
    org_domains : 自組織ドメインのリスト(scoring.yaml から渡す)
    """
    inner = report.inner
    urls = extract_urls(inner)
    signals: list[Signal] = []

    if not urls:
        return UrlAnalysis(urls=[], signals=[])

    org_set = {org_domain(d) for d in org_domains}

    # 差出人のドメイン(U08の比較用)
    _, from_addr = get_addr(inner, "From")
    from_org = org_domain(domain_of(from_addr))

    # 類似判定の比較対象。自組織 + 著名ブランド
    lookalike_targets = org_set | COMMON_BRAND_DOMAINS

    # 同じホストに対して同じ判定を繰り返さないための記録。
    # メール1通に同一ドメインのリンクが10個あっても、配点は1回だけにする
    checked_hosts: set[str] = set()

    for u in urls:
        if not u.host:
            continue

        # ================================================================
        # URLごとの判定（同一ホストでもURLが違えば個別に見る）
        # ================================================================

        # ---- U07: URLに認証情報が埋め込まれている ----
        # http://www.bank.co.jp@evil.example/ の形式。
        # @の前は無視されるため、正規サイトに見せかけられる
        if _USERINFO_RE.match(u.url):
            signals.append(Signal("U07", defang(u.url)[:100]))

        # ---- U04: 表示テキストとリンク先の不一致 ----
        # アンカーテキストがURL形式なのに、hrefのドメインと違う場合。
        # 「https://www.bank.co.jp」と表示して evil.example へ飛ばす手口。
        # アンカーがURL形式でない場合(「こちら」など)は判定対象外
        if u.anchor_text:
            anchor_urls = _URL_RE.findall(u.anchor_text)
            if anchor_urls:
                anchor_org = org_domain(_normalize_host(anchor_urls[0]))
                if anchor_org and u.org and anchor_org != u.org:
                    signals.append(Signal(
                        "U04", f"表示='{anchor_org}' / 実際='{u.org}'"
                    ))

        # ================================================================
        # ホストごとの判定（1ホスト1回だけ）
        # ================================================================
        if u.host in checked_hosts:
            continue
        checked_hosts.add(u.host)

        # ---- U03: IDNホモグラフ ----
        mixed, chars = _has_mixed_script(u.host)
        if mixed:
            signals.append(Signal("U03", f"{u.host} に異体字 '{chars}' が混入"))

        # ---- U02: 自組織・著名ブランドに酷似 ----
        # 編集距離1〜2は「一文字だけ違う」偽装ドメイン。
        # 距離0(完全一致)は正規なので、その時点でこのホストの判定を打ち切る
        for target in lookalike_targets:
            if u.org == target:
                break
            dist = _levenshtein(u.org, target)
            if 1 <= dist <= 2:
                signals.append(Signal(
                    "U02", f"{u.org} は {target} に酷似（編集距離{dist}）"
                ))
                break

        # ---- U06: 短縮URL / オープンリダイレクタ ----
        if _is_shortener(u.host):
            signals.append(Signal("U06", f"短縮URL: {u.host}"))
        elif _REDIRECT_PARAM_RE.search(unquote(u.url)):
            signals.append(Signal("U06", f"リダイレクタ: {defang(u.url)[:80]}"))

    # ================================================================
    # メール全体で1回だけ行う判定
    # ================================================================

    # ---- U08: 差出人ドメインと本文URLが無関係 ----
    # URLごとに立てると配点が積み上がりすぎるため、全体で1回。
    # 「差出人と同じ組織のURLが1つもない」場合のみ立てる。
    # 配信サービス経由などで別ドメインが混ざるのは正常なため、
    # この厳しめの条件で誤検知を抑える
    if from_org:
        url_orgs = {u.org for u in urls if u.org}
        if url_orgs and from_org not in url_orgs:
            # 自組織や著名ブランドへのリンクは正常な参照なので除外して判断
            unrelated = url_orgs - lookalike_targets
            if unrelated:
                sample = ", ".join(sorted(unrelated)[:3])
                signals.append(Signal("U08", f"From={from_org} / URL={sample}"))

    return UrlAnalysis(urls=urls, signals=signals)
