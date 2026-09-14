# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/scoring.py

検出されたシグナルのリストから、スコアと最終判定を算出する。

設計方針:
  - 「何を検出するか」(detector.py) と「どう評価するか」(このファイル) を分離する。
    こうすることで、配点の調整は scoring.yaml だけで完結し、
    検出ロジックのコードを触らずに運用中のチューニングができる。
  - スコアはルールベースで決定する。LLM は文脈系(C系)のシグナルを
    立てるだけで、最終判定そのものは行わない。
  - mode(attached/inline)による確度の差は、スコアに下駄を履かせるのではなく
    閾値を下げることで表現する。スコアに補正を入れると、
    レポートに出す点数の意味が壊れるため。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

log = logging.getLogger(__name__)

# 判定の種類。この4つ以外は返さない
Verdict = Literal["malicious", "suspicious", "unknown", "benign"]

# 即時悪性のときに入れる擬似スコア。
# 通常の積算と区別するため、到達し得ない大きな値を使う
INSTANT_SCORE = 999

DEFAULT_RULES_PATH = "/opt/phish/rules/scoring.yaml"


@dataclass
class Signal:
    """
    検出された1つのシグナル。

    rule_id : scoring.yaml の rules[].id と対応する識別子（"H01" など）
    detail  : 具体的に何を検出したか（レポートの根拠として表示する）
              例: "Reply-To: attacker@evil.example"
    """
    rule_id: str
    detail: str = ""


@dataclass
class ScoredSignal:
    """スコア算出後のシグナル。レポート生成で使うため配点と文面を保持する"""
    rule_id: str
    detail: str
    score: int
    category: str
    label: str          # 担当者向けの簡潔な表示
    description: str    # 報告者向けの平易な説明


@dataclass
class Result:
    """解析エンジンがレポート生成側へ渡す最終結果"""
    verdict: Verdict
    score: int
    confidence: str
    mode: str
    # 適用されたシグナル（配点と文面つき）。減点分も含む
    signals: list[ScoredSignal] = field(default_factory=list)
    # 即時悪性で確定した場合、その理由。通常判定なら None
    instant_reason: str | None = None
    # YAML に定義がなく無視した rule_id。実装漏れの検知に使う
    unknown_rule_ids: list[str] = field(default_factory=list)
    # 適用された閾値（レポートに「100点中○点」と出すために保持）
    threshold_malicious: int = 0
    threshold_suspicious: int = 0

    @property
    def is_instant(self) -> bool:
        return self.instant_reason is not None

    def signals_by_category(self, category: str) -> list[ScoredSignal]:
        """カテゴリ別にシグナルを取り出す（レポートの章立てに使う）"""
        return [s for s in self.signals if s.category == category]

    def to_dict(self) -> dict:
        """n8n へ Webhook で渡すための辞書化"""
        return {
            "verdict": self.verdict,
            "score": None if self.is_instant else self.score,
            "instant": self.is_instant,
            "instant_reason": self.instant_reason,
            "confidence": self.confidence,
            "mode": self.mode,
            "threshold_malicious": self.threshold_malicious,
            "signals": [
                {
                    "id": s.rule_id,
                    "label": s.label,
                    "description": s.description,
                    "detail": s.detail,
                    "score": s.score,
                    "category": s.category,
                }
                for s in self.signals
            ],
        }


class Scorer:
    """scoring.yaml を読み込み、シグナル群から判定を算出する"""

    def __init__(self, rules_path: str | Path = DEFAULT_RULES_PATH):
        self.rules_path = Path(rules_path)
        self._load()

    # ------------------------------------------------------------------
    # 設定の読み込み
    # ------------------------------------------------------------------
    def _load(self) -> None:
        with open(self.rules_path, encoding="utf-8") as f:
            self.cfg = yaml.safe_load(f)

        # ルールを id で引けるよう辞書化する。
        # 毎回リストを走査すると、シグナルが増えたときに無駄が出る
        self.rules: dict[str, dict] = {r["id"]: r for r in self.cfg.get("rules", [])}

        # 設定ファイルの妥当性を起動時に検証する。
        # 運用中に YAML を編集して壊した場合、ここで気づけるようにする
        self._validate()

    def _validate(self) -> None:
        """YAML の整合性チェック。問題があれば例外を投げて起動を止める"""
        if not self.rules:
            raise ValueError(f"{self.rules_path}: rules が空です")

        # 必須キーの欠落を検出する
        for rid, rule in self.rules.items():
            for key in ("score", "category", "label", "description"):
                if key not in rule:
                    raise ValueError(f"ルール {rid} に '{key}' がありません")

        # instant_malicious に、存在しない rule_id が書かれていないか確認する
        for rid in self.cfg.get("instant_malicious", []):
            if rid not in self.rules:
                raise ValueError(f"instant_malicious の {rid} が rules に存在しません")

        for combo in self.cfg.get("instant_malicious_combo", []):
            for rid in combo.get("rules", []):
                if rid not in self.rules:
                    raise ValueError(
                        f"instant_malicious_combo の {rid} が rules に存在しません"
                    )

        # 閾値の大小関係が破綻していないか確認する。
        # malicious < suspicious のような設定は判定を壊す
        for mode, th in self.cfg.get("thresholds", {}).items():
            if not (th["malicious"] > th["suspicious"] > th["unknown"]):
                raise ValueError(
                    f"thresholds.{mode} の大小関係が不正です: {th}"
                )

    def reload(self) -> None:
        """
        運用中に YAML を書き換えたときの再読み込み。
        検証に失敗した場合は例外が飛ぶが、既存の self.cfg は
        _load() 内で上書きされる前に例外が出るため、壊れた設定は適用されない。
        """
        self._load()
        log.info("scoring rules reloaded from %s", self.rules_path)

    # ------------------------------------------------------------------
    # 組織ドメインの参照（detector.py から使う）
    # ------------------------------------------------------------------
    @property
    def org_domains(self) -> list[str]:
        return self.cfg.get("organization", {}).get("domains", [])

    @property
    def include_subdomains(self) -> bool:
        return self.cfg.get("organization", {}).get("include_subdomains", True)

    def is_org_domain(self, domain: str) -> bool:
        """
        指定ドメインが自組織のものか判定する。

        重要: 「含む」ではなく「完全一致またはサブドメイン」で判定すること。
        単純な部分文字列一致にすると example.ac.jp.evil.com のような
        詐称ドメインを自組織と誤認し、詐称を見逃す。
        """
        if not domain:
            return False
        d = domain.lower().rstrip(".")

        for org in self.org_domains:
            org = org.lower().rstrip(".")
            if d == org:
                return True
            # サブドメインは「.example.ac.jp」で終わる場合のみ該当。
            # 前方にドットを付けることで example.ac.jp.evil.com を除外する
            if self.include_subdomains and d.endswith("." + org):
                return True
        return False

    # ------------------------------------------------------------------
    # スコア算出
    # ------------------------------------------------------------------
    def score(self, signals: list[Signal], mode: str = "attached") -> Result:
        """
        シグナルのリストから最終判定を返す。

        mode:
          "attached" = 添付として転送された（元メールのヘッダーが完全に残っている）
          "inline"   = 通常転送（ヘッダーが失われている）
        """
        thresholds = self.cfg["thresholds"]
        # 未知の mode が来ても落ちないよう、attached をフォールバックにする
        th = thresholds.get(mode, thresholds["attached"])

        confidence = "高" if mode == "attached" else "中（ヘッダー未取得）"

        # 同じ rule_id が複数回検出されることがある（URLが3つとも悪性など）。
        # 配点の二重計上を避けるため、id 単位で1回だけ数える。
        # detail は結合して「どれが該当したか」を残す
        merged: dict[str, list[str]] = {}
        order: list[str] = []
        for s in signals:
            if s.rule_id not in merged:
                merged[s.rule_id] = []
                order.append(s.rule_id)
            if s.detail:
                merged[s.rule_id].append(s.detail)

        detected_ids = set(order)

        # --- 適用ルールの解決 ---
        scored: list[ScoredSignal] = []
        unknown_ids: list[str] = []

        for rid in order:
            rule = self.rules.get(rid)
            if rule is None:
                # YAML に定義がない id。detector 側だけ先行実装された場合に起きる。
                # 落とさず記録だけして続行する（解析を止めないため）
                unknown_ids.append(rid)
                log.warning("未定義のルールIDを無視しました: %s", rid)
                continue

            scored.append(
                ScoredSignal(
                    rule_id=rid,
                    detail=" / ".join(merged[rid]),
                    score=rule["score"],
                    category=rule["category"],
                    label=rule["label"],
                    description=rule["description"],
                )
            )

        # --- 即時悪性の判定（単独ルール）---
        # 既知マルウェアや既知悪性URLは、他のシグナルの積み上げを待たず確定させる
        instant = set(self.cfg.get("instant_malicious", []))
        hit = detected_ids & instant
        if hit:
            # 複数該当した場合は id 順で先頭を理由に採用する（再現性のため）
            rid = sorted(hit)[0]
            return Result(
                verdict="malicious",
                score=INSTANT_SCORE,
                confidence=confidence,
                mode=mode,
                signals=scored,
                instant_reason=self.rules[rid]["label"],
                unknown_rule_ids=unknown_ids,
                threshold_malicious=th["malicious"],
                threshold_suspicious=th["suspicious"],
            )

        # --- 即時悪性の判定（複合条件）---
        # 単独では断定できないが、組み合わせで確定するパターン。
        # 例: 自組織ドメイン詐称(H08) かつ DMARC失敗(H01)
        for combo in self.cfg.get("instant_malicious_combo", []):
            if set(combo["rules"]).issubset(detected_ids):
                return Result(
                    verdict="malicious",
                    score=INSTANT_SCORE,
                    confidence=confidence,
                    mode=mode,
                    signals=scored,
                    instant_reason=combo["reason"],
                    unknown_rule_ids=unknown_ids,
                    threshold_malicious=th["malicious"],
                    threshold_suspicious=th["suspicious"],
                )

        # --- 通常のスコア積算 ---
        total = sum(s.score for s in scored)

        # 減点(S系)により負になり得るので 0 を下限にする。
        # 負の点数はレポートに出すと意味不明なため
        total = max(0, total)

        if total >= th["malicious"]:
            verdict: Verdict = "malicious"
        elif total >= th["suspicious"]:
            verdict = "suspicious"
        elif total >= th["unknown"]:
            verdict = "unknown"
        else:
            verdict = "benign"

        return Result(
            verdict=verdict,
            score=total,
            confidence=confidence,
            mode=mode,
            signals=scored,
            unknown_rule_ids=unknown_ids,
            threshold_malicious=th["malicious"],
            threshold_suspicious=th["suspicious"],
        )


# 判定値を日本語表示するための対応表。
# レポート生成側で使う
VERDICT_JA: dict[str, str] = {
    "malicious": "悪性",
    "suspicious": "疑わしい",
    "unknown": "判定不能",
    "benign": "問題なし",
}


if __name__ == "__main__":
    # 単体実行時の簡易確認。
    # python3 /opt/phish/analyzer/scoring.py で動作する
    logging.basicConfig(level=logging.INFO)
    s = Scorer()
    print(f"ルール数: {len(s.rules)}")
    print(f"組織ドメイン: {s.org_domains}")
    print(f"example.ac.jp は自組織か: {s.is_org_domain('example.ac.jp')}")
    print(f"imc.example.ac.jp は自組織か: {s.is_org_domain('imc.example.ac.jp')}")
    print(f"example.ac.jp.evil.com は自組織か: {s.is_org_domain('example.ac.jp.evil.com')}")
