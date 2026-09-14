# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/config.py

設定の集約。

設定が環境変数・systemd unit・シェルの rc ファイルに散らばると、
実行経路によって挙動が変わる。実際、systemd 経由では設定されている
PHISH_AUTHSERV_ID が手動実行では未設定になり、判定が食い違う
事態が起きた。設定は1箇所にまとめ、どこから実行しても同じ結果になる
ようにする。

優先順位:
  1. 環境変数 PHISH_<KEY>   （コンテナ化や一時的な上書き用）
  2. config.yaml            （通常の設定方法）
  3. コード内の既定値       （設定ファイルが無くても動く）

設定ファイルの場所は PHISH_CONFIG で変更できる。
既定は /etc/phish/config.yaml で、無ければ
<このファイルのあるディレクトリ>/../config/config.yaml を探す。
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

# 設定ファイルの探索順。最初に見つかったものを使う
_SEARCH_PATHS = [
    os.environ.get("PHISH_CONFIG", ""),
    "/etc/phish/config.yaml",
    str(Path(__file__).resolve().parent.parent / "config" / "config.yaml"),
]

# 既定値。設定ファイルが無くても動くようにするための最終フォールバック。
# キーは "セクション.項目" のドット区切りで表す
_DEFAULTS: dict[str, Any] = {
    # ---- 受信MTA ----
    # 自前の受信MTAが Authentication-Results に付与する AuthservID。
    # 未設定だと転送元の検証結果を元メールのものと誤認するため、
    # 実運用では必ず設定すること
    "mta.authserv_id": "",

    # ---- 検体の保管 ----
    "spool.path": "/var/spool/phish",

    # ---- 通知 ----
    # シャドーモード。運用開始から最低2週間は true のままにして、
    # 実データで誤検知の傾向を掴んでから false にする
    "notify.shadow_mode": True,
    "notify.webhook": "http://127.0.0.1:5678/webhook/phish-result",
    "notify.contact_name": "情報システム担当",

    # ---- 脅威インテリ(OpenCTI) ----
    "opencti.url": "",
    "opencti.token": "",
    # 接続情報を別ファイル(.env)から読む場合の場所。
    # url/token を直接書くより、既存の設定を共有できる
    "opencti.env_file": "",
    # スコアの足切り。低くすると正規ドメインを拾う。
    # 多くのフィードは既定値のままスコアを付けるため、
    # スコアは信頼性の指標として機能しないことに注意
    "opencti.min_score": 70,
    "opencti.cache_db": "/var/spool/phish/enrich-cache.db",
    "opencti.cache_ttl_days": 7,
    # WHOIS による新規ドメイン判定。外部へ問い合わせが発生し、
    # 照会したドメインが WHOIS サーバー運用者に見えるため既定は無効
    "opencti.enable_whois": False,

    # ---- LLM ----
    "llm.enabled": True,
    "llm.url": "http://127.0.0.1:11434",
    # 思考トークンを出すモデル(qwen3系など)は構造化出力に使えない
    "llm.model": "gemma3:4b",
    "llm.timeout": 60,
    "llm.max_body_chars": 4000,

    # ---- キャッシュ ----
    # tldextract のキャッシュ。ProtectHome=read-only 下では
    # ~/.cache に書けないため、書き込み可能な場所を指定する
    "cache.tldextract": "/var/cache/phish-tldextract",

    # ---- ルール ----
    "rules.path": "/opt/phish/rules/scoring.yaml",

    # ---- pull (VPS からの取得) ----
    "pull.ssh_target": "",
    "pull.ssh_key": "",
    "pull.api_url": "http://127.0.0.1:8081/ingest/mail",
}


def _env_key(key: str) -> str:
    """
    "llm.model" -> "PHISH_LLM_MODEL" に変換する。

    既存の環境変数名と互換を保つため、この規則を崩さないこと
    """
    return "PHISH_" + key.upper().replace(".", "_")


def _coerce(value: str, default: Any) -> Any:
    """
    環境変数は文字列で来るので、既定値の型に合わせて変換する。

    bool は "1"/"true"/"yes" を真として扱う。
    "0" や "false" を True と解釈すると設定が無視されるため、
    ここは明示的に判定する
    """
    if isinstance(default, bool):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        try:
            return int(value)
        except ValueError:
            log.warning("整数として読めない値: %r（既定値を使用）", value)
            return default
    return value


class Config:
    """設定の読み取り。読み込みは起動時に1回だけ行う"""

    def __init__(self, path: str | None = None):
        self.path: str = ""
        self.data: dict = {}

        candidates = [path] if path else _SEARCH_PATHS
        for p in candidates:
            if not p:
                continue
            f = Path(p)
            if not f.is_file():
                continue
            try:
                self.data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                self.path = str(f)
                break
            except Exception as e:
                # 設定ファイルが壊れていても起動は続ける。
                # 既定値で動く方が、全く動かないよりましなため
                log.error("設定ファイルを読めません %s: %s", f, e)

        if not self.path:
            log.info("設定ファイルが見つかりません。既定値と環境変数のみ使用します")

    def _from_yaml(self, key: str) -> Any:
        """ドット区切りのキーで、ネストした辞書から値を取り出す"""
        node: Any = self.data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def get(self, key: str, default: Any = None) -> Any:
        """
        設定値を取得する。

        優先順位: 環境変数 > config.yaml > _DEFAULTS > 引数の default
        """
        fallback = _DEFAULTS.get(key, default)

        # 1. 環境変数
        env = os.environ.get(_env_key(key))
        if env is not None and env != "":
            return _coerce(env, fallback)

        # 2. config.yaml
        value = self._from_yaml(key)
        if value is not None:
            return value

        # 3. 既定値
        return fallback

    def describe(self, keys: list[str]) -> str:
        """
        起動ログ用に、主要な設定値を1行にまとめる。
        トークンなどの秘密情報は含めないこと
        """
        parts = []
        for k in keys:
            parts.append(f"{k}={self.get(k)}")
        return " / ".join(parts)


# モジュール読み込み時に1回だけ生成する。
# 各モジュールは from config import cfg で参照する
cfg = Config()

if cfg.path:
    log.info("設定ファイル: %s", cfg.path)


if __name__ == "__main__":
    # 現在の設定値を確認する。
    #   python3 config.py
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    print(f"設定ファイル: {cfg.path or '(なし。既定値を使用)'}")
    print()

    for key in sorted(_DEFAULTS):
        value = cfg.get(key)
        # トークンは値を出さない
        if "token" in key:
            value = "(設定済み)" if value else "(未設定)"

        # どこから来た値かを示す
        if os.environ.get(_env_key(key)):
            src = "env"
        elif cfg._from_yaml(key) is not None:
            src = "yaml"
        else:
            src = "既定"

        print(f"  {key:28s} = {value!r:40s} [{src}]")
