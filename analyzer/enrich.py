# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/enrich.py

外部の脅威インテリと突き合わせて、追加のシグナルを検出する。

対応シグナル:
  U01 : 既知の悪性URL / ドメイン（OpenCTI）
  A01 : 既知マルウェアのハッシュ（OpenCTI）
  H09 : 既知の悪性IP（OpenCTI）
  H15 : 既知の攻撃者メールアドレス（OpenCTI）
  U05 : 新規登録ドメイン（WHOIS。既定では無効）

設計上の重要な前提:

  OpenCTI の x_opencti_score は、必ずしも信頼性の指標として
  機能しない。ある環境で実測したところ、Domain-Name 20万件のうち
  18万件がスコア51〜70に密集しており、大半のフィードが既定値のまま
  投入されていた。実際 google.com が score=60 で登録されていた。

  そのため:
    - スコアの足切りを設ける（既定は70超。環境に応じて要調整）
    - 自組織ドメインと著名ブランドは照会自体をスキップする
    - U01 / A01 を「即時悪性」にしない。誤ヒット1件で報告者に
      「危険です」と誤通知する事故を避けるため、積算スコアに留める

  高スコア帯の実体は、攻撃用に作られたドメインより
  「侵害された正規サイト」が多い（URLhaus / Feodo Tracker 系）。
  ヒットすれば確度は高いが、侵害が解消されて現在は正常に
  戻っている可能性もあるため、単独では断定しない。

  導入時は、自組織や著名サービスのドメインを実際に照会してみて、
  誤ヒットしないスコア閾値を決めること。

安全上の原則:
  - URL を自分で GET しない。解析基盤のIPが露見し、SSRFの踏み台にもなる
  - 外部へ送るのはドメイン・IP・ハッシュのみ。本文は絶対に送らない
  - 照会に失敗しても解析を止めない。シグナルなしで続行する
  - GraphQL の errors を必ず検出する。握りつぶすと「照会失敗」を
    「ヒットなし＝安全」と誤認し、悪性を見逃し続けることになる
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from config import cfg
from detector_attach import AttachAnalysis
from detector_header import org_domain, extract_sender_ip
from detector_url import COMMON_BRAND_DOMAINS, UrlAnalysis
from parser import ParsedReport, domain_of, get_addr
from scoring import Signal

log = logging.getLogger(__name__)

# ---- 設定 ----
# スコアの足切り。低くすると正規ドメインを拾う。
# 環境によってフィードの構成が違うため、導入時に実測して決めること
MIN_SCORE = int(cfg.get("opencti.min_score"))

# 1通あたりの照会上限。1件0.5秒程度かかるため、多すぎると解析が遅くなる
MAX_DOMAIN_QUERIES = 8
MAX_HASH_QUERIES = 5

HTTP_TIMEOUT = 10

# キャッシュ。同じドメインを何度も照会しないようにする
CACHE_DB = Path(cfg.get("opencti.cache_db"))
CACHE_TTL = int(cfg.get("opencti.cache_ttl_days")) * 24 * 3600

# WHOIS による新規ドメイン判定(U05)。
# 外部への通信が発生し、照会したドメインが WHOIS サーバー運用者に
# 見えるため既定では無効
ENABLE_WHOIS = bool(cfg.get("opencti.enable_whois"))
NEW_DOMAIN_DAYS = 30


@dataclass
class EnrichResult:
    signals: list[Signal] = field(default_factory=list)
    # 照会の可否。担当者向けレポートに「照会できなかった」と出すために使う
    available: bool = True
    error: str = ""
    queried: int = 0
    hits: list[dict] = field(default_factory=list)


# ----------------------------------------------------------------------
# 接続情報の解決
# ----------------------------------------------------------------------

def _load_from_env_file(path: Path) -> tuple[str, str]:
    """
    .env 形式のファイルから OPENCTI_URL / OPENCTI_TOKEN を読む。

    既存システムと設定を共有したい場合に使う。
    python-dotenv には依存せず自前で読むので、
    余計なキーが含まれていても無視する。
    """
    url = token = ""
    if not path.is_file():
        log.warning("opencti.env_file が見つかりません: %s", path)
        return url, token

    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            # 値がクォートで囲まれている場合に備えて剥がす
            v = v.strip().strip('"').strip("'")
            if k == "OPENCTI_URL":
                url = v
            elif k == "OPENCTI_TOKEN":
                token = v
    except Exception as e:
        log.warning("env_file の読み込みに失敗 %s: %s", path, e)

    return url, token


def _resolve_connection() -> tuple[str, str]:
    """
    OpenCTI の接続情報を決定する。

    優先順位:
      1. config.yaml の opencti.url / opencti.token
         （環境変数 PHISH_OPENCTI_URL / PHISH_OPENCTI_TOKEN で上書き可）
      2. config.yaml の opencti.env_file が指す .env の中身

    公開版では .env を持たない利用者が大半なので直接指定を優先し、
    既存システムと設定を共有したい場合のために env_file も残す。
    """
    url = str(cfg.get("opencti.url") or "").rstrip("/")
    token = str(cfg.get("opencti.token") or "")

    if url and token:
        return url, token

    env_file = str(cfg.get("opencti.env_file") or "")
    if env_file:
        f_url, f_token = _load_from_env_file(Path(env_file))
        url = url or f_url.rstrip("/")
        token = token or f_token

    return url, token


OPENCTI_URL, OPENCTI_TOKEN = _resolve_connection()


# ----------------------------------------------------------------------
# キャッシュ
# ----------------------------------------------------------------------

def _cache_init() -> sqlite3.Connection | None:
    """キャッシュDBを開く。失敗してもエンリッチ自体は続行できる"""
    try:
        CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(CACHE_DB, timeout=5)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lookup (
                value TEXT PRIMARY KEY,
                result TEXT NOT NULL,
                ts INTEGER NOT NULL
            )
        """)
        conn.commit()
        return conn
    except Exception as e:
        log.warning("キャッシュを開けません: %s", e)
        return None


def _cache_get(conn, value: str) -> dict | None:
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT result, ts FROM lookup WHERE value = ?", (value,)
        ).fetchone()
        if row and (time.time() - row[1]) < CACHE_TTL:
            return json.loads(row[0])
    except Exception:
        pass
    return None


def _cache_put(conn, value: str, result: dict) -> None:
    if conn is None:
        return
    try:
        conn.execute(
            "INSERT OR REPLACE INTO lookup(value, result, ts) VALUES (?, ?, ?)",
            (value, json.dumps(result, ensure_ascii=False), int(time.time())),
        )
        conn.commit()
    except Exception:
        pass


# ----------------------------------------------------------------------
# OpenCTI 照会
# ----------------------------------------------------------------------

# OpenCTI のフィルタは values の要素が Any! 型で定義されているため、
# GraphQL 変数を String! で宣言すると型不一致でエラーになる。
#   Variable "$value" of type "String!" used in position expecting type "Any!"
# そのため変数を使わず、値を JSON エンコードして埋め込む。
# json.dumps を通すので、クォートや制御文字によるインジェクションは起きない。
#
# value の完全一致(operator: eq)で引く。search: を使うと
# example.com が example.community にヒットするなど誤検知の温床になる。
#
# 取得フィールドは最小限にとどめる。objectLabel や createdBy は
# OpenCTI のバージョンによってスキーマが異なることがあり、
# 1フィールドの不一致でクエリ全体が失敗するため。
_QUERY_TEMPLATE = """
{
  stixCyberObservables(
    first: 5
    filters: {
      mode: and
      filters: [{ key: "value", values: [%s], operator: eq }]
      filterGroups: []
    }
  ) {
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_score
      }
    }
  }
}
"""


def _query_opencti(session, conn, value: str) -> dict:
    """
    1つの値を OpenCTI に問い合わせる。

    戻り値:
      ヒット時   {"hit": True, "score": int, "type": str, "value": str}
      未ヒット時 {"hit": False}
      失敗時     {"hit": False, "error": "..."}
    """
    cached = _cache_get(conn, value)
    if cached is not None:
        return cached

    query = _QUERY_TEMPLATE % json.dumps(value)

    try:
        resp = session.post(
            f"{OPENCTI_URL}/graphql",
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}"},
            json={"query": query},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
    except Exception as e:
        # 1件失敗しても他の照会は続ける。ネットワーク障害はキャッシュしない
        log.warning("OpenCTI 照会に失敗 (%s): %s", value, e)
        return {"hit": False, "error": str(e)}

    # GraphQL は HTTP 200 でも errors を返す。
    # これを見落とすと「照会失敗」を「ヒットなし＝安全」と誤認し、
    # 悪性を見逃し続けることになる
    if body.get("errors"):
        msg = body["errors"][0].get("message", "unknown")
        log.error("OpenCTI GraphQL エラー (%s): %s", value, msg)
        # エラーはキャッシュしない。設定を直したら次回すぐ反映されるように
        return {"hit": False, "error": f"graphql: {msg}"}

    edges = ((body.get("data") or {})
             .get("stixCyberObservables", {})
             .get("edges", []))

    # スコアが閾値を超えるものだけを採用する。
    # score が None の場合があるので 0 として扱う
    best = None
    for e in edges:
        node = e.get("node", {})
        score = node.get("x_opencti_score") or 0
        if score <= MIN_SCORE:
            continue
        if best is None or score > best["score"]:
            best = {
                "hit": True,
                "score": score,
                "type": node.get("entity_type", ""),
                "value": node.get("observable_value", value),
            }

    result = best or {"hit": False}
    _cache_put(conn, value, result)
    return result


# ----------------------------------------------------------------------
# WHOIS（U05: 新規登録ドメイン）
# ----------------------------------------------------------------------

def _domain_age_days(domain: str) -> int | None:
    """
    ドメインの登録からの経過日数を返す。

    外部の WHOIS サーバーへ問い合わせるため、既定では無効。
    有効にする場合、照会対象のドメインが WHOIS サーバーの運用者に
    見える点に留意すること。
    """
    import re
    import subprocess
    from datetime import datetime, timezone

    try:
        out = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except Exception as e:
        log.warning("whois に失敗 (%s): %s", domain, e)
        return None

    # Creation Date / Registered on など表記揺れが多いので複数パターンを試す
    patterns = [
        r"(?:Creation Date|Created On|Registered on|created)\s*:\s*"
        r"([0-9]{4}-[0-9]{2}-[0-9]{2})",
        r"(?:Creation Date|Created On)\s*:\s*([0-9]{4}/[0-9]{2}/[0-9]{2})",
    ]
    for p in patterns:
        m = re.search(p, out, re.IGNORECASE)
        if not m:
            continue
        raw = m.group(1).replace("/", "-")
        try:
            created = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).days
        except Exception:
            continue
    return None


# ----------------------------------------------------------------------
# 検出本体
# ----------------------------------------------------------------------

def enrich(
    report: ParsedReport,
    url_result: UrlAnalysis,
    attach_result: AttachAnalysis,
    org_domains: list[str],
) -> EnrichResult:
    """
    脅威インテリと突き合わせて追加シグナルを返す。

    OpenCTI が未設定・到達不能でも例外を投げず、
    available=False を返して解析を継続させる。
    """
    if not (OPENCTI_URL and OPENCTI_TOKEN):
        return EnrichResult(available=False, error="OpenCTI 未設定")

    signals: list[Signal] = []
    hits: list[dict] = []
    errors: list[str] = []
    queried = 0

    # 照会をスキップするドメイン。
    # 自組織と著名ブランドは、誤ヒットの害が大きいので問い合わせない。
    # 実際 google.com が score=60 で登録されている環境があった
    skip = {org_domain(d) for d in org_domains} | COMMON_BRAND_DOMAINS

    conn = _cache_init()
    session = requests.Session()

    def lookup(value: str) -> dict:
        """照会して件数とエラーを記録する"""
        nonlocal queried
        r = _query_opencti(session, conn, value)
        queried += 1
        if r.get("error"):
            errors.append(r["error"])
        return r

    try:
        # ================================================================
        # U01: URL / ドメイン
        # ================================================================
        # ホスト単位に重複排除し、組織ドメインでも引く。
        # www.evil.example が未登録でも evil.example が登録されている場合がある
        candidates: list[str] = []
        for host in url_result.unique_hosts:
            if not host:
                continue
            org = org_domain(host)
            if org in skip:
                continue
            for v in (host, org):
                if v and v not in candidates:
                    candidates.append(v)

        for value in candidates[:MAX_DOMAIN_QUERIES]:
            r = lookup(value)
            if r.get("hit"):
                signals.append(Signal(
                    "U01", f"{value} (OpenCTI score={r['score']})"
                ))
                hits.append({"ioc": value, **r})
                # 1通につき1回で十分。配点の二重計上は scoring 側でも
                # 防がれるが、照会回数を抑える意味でここで打ち切る
                break

        # ================================================================
        # A01: 添付ファイルのハッシュ
        # ================================================================
        for att in attach_result.attachments[:MAX_HASH_QUERIES]:
            if not att.sha256:
                continue
            r = lookup(att.sha256)
            if r.get("hit"):
                signals.append(Signal(
                    "A01", f"{att.filename} (OpenCTI score={r['score']})"
                ))
                hits.append({"ioc": att.sha256, "filename": att.filename, **r})

        # ================================================================
        # H09: 送信元IP
        # ================================================================
        sender_ip = extract_sender_ip(report.inner)
        if sender_ip:
            r = lookup(sender_ip)
            if r.get("hit"):
                signals.append(Signal(
                    "H09", f"{sender_ip} (OpenCTI score={r['score']})"
                ))
                hits.append({"ioc": sender_ip, **r})

        # ================================================================
        # H15: 差出人メールアドレス
        # ================================================================
        # Email-Addr の登録件数は少ないことが多いが、
        # ヒットすれば確度は極めて高い
        _, from_addr = get_addr(report.inner, "From")
        if from_addr and "@" in from_addr:
            if org_domain(domain_of(from_addr)) not in skip:
                r = lookup(from_addr.lower())
                if r.get("hit"):
                    signals.append(Signal(
                        "H15", f"{from_addr} (OpenCTI score={r['score']})"
                    ))
                    hits.append({"ioc": from_addr, **r})

        # ================================================================
        # U05: 新規登録ドメイン（WHOIS。既定では無効）
        # ================================================================
        if ENABLE_WHOIS:
            for host in url_result.unique_hosts[:3]:
                org = org_domain(host)
                if not org or org in skip:
                    continue
                age = _domain_age_days(org)
                if age is not None and age <= NEW_DOMAIN_DAYS:
                    signals.append(Signal("U05", f"{org} は登録から{age}日"))
                    break

    finally:
        session.close()
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    # 照会が1件でも失敗していたら、その旨を担当者に伝えられるようにする。
    # 「ヒットなし」と「照会できなかった」は意味が全く違う
    return EnrichResult(
        signals=signals,
        available=not errors,
        error="; ".join(dict.fromkeys(errors))[:300],
        queried=queried,
        hits=hits,
    )


if __name__ == "__main__":
    # 単体実行時の疎通確認。
    #   python3 enrich.py [照会したい値...]
    #
    # 導入時は、自組織や著名サービスのドメインを引いてみて、
    # 誤ヒットしないスコア閾値になっているか確認すること
    import sys

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(message)s")

    print(f"OpenCTI URL : {OPENCTI_URL or '(未設定)'}")
    print(f"トークン    : {'設定済み' if OPENCTI_TOKEN else '未設定'}")
    print(f"スコア閾値  : {MIN_SCORE} 超")
    print(f"キャッシュ  : {CACHE_DB}（{CACHE_TTL // 86400}日）")
    print(f"WHOIS       : {'有効' if ENABLE_WHOIS else '無効'}")
    print()

    if not (OPENCTI_URL and OPENCTI_TOKEN):
        print("接続情報が未設定です。config.yaml の opencti を確認してください",
              file=sys.stderr)
        sys.exit(1)

    targets = sys.argv[1:] or ["google.com", "microsoft.com"]

    s = requests.Session()
    c = _cache_init()
    for v in targets:
        r = _query_opencti(s, c, v)
        mark = "HIT " if r.get("hit") else "--- "
        print(f"{mark}{v:28s} {r}")
