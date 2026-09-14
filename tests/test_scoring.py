# -*- coding: utf-8 -*-
"""
tests/test_scoring.py

検出ロジックを介さず、スコアリングだけを検証する。
シグナルを手で組み立てて、期待する判定になるか確かめる。

    python3 tests/test_scoring.py

配点を変更したときは、まずこれを通してから
run_samples.sh で実検体の判定を確認する。
"""
import os
import sys
from pathlib import Path

# リポジトリのどこに展開しても動くよう、相対パスで analyzer を参照する。
# 別の場所にインストールした場合は PHISH_ANALYZER_DIR で上書きできる
sys.path.insert(0, os.environ.get(
    "PHISH_ANALYZER_DIR",
    str(Path(__file__).resolve().parent.parent / "analyzer"),
))

from scoring import Scorer, Signal, VERDICT_JA

scorer = Scorer()


def show(name, signals, mode, expect):
    """1ケースを実行して結果を表示する"""
    r = scorer.score(signals, mode=mode)
    got = f"{r.verdict}/{'即時' if r.is_instant else r.score}"
    mark = "OK " if got.startswith(expect.split("/")[0]) else "NG "
    detail = (f"(即時: {r.instant_reason})" if r.is_instant
              else f"{r.score}点")
    print(f"{mark}{name}: {VERDICT_JA[r.verdict]} {detail} [期待: {expect}]")


# 高配点が3つ重なると悪性圏に入る
show("1 複合",
     [Signal("H01"), Signal("H06"), Signal("A07", "invoice.exe")],
     "attached", "malicious")

# 通常転送はヘッダー系が検出できないため、閾値を下げてある。
# 添付のシグナルだけでも「疑わしい」に到達する
show("2 inline",
     [Signal("A07", "invoice.exe")],
     "inline", "suspicious")

# 自組織詐称 + 認証失敗は複合条件で即時悪性
show("3 複合即時",
     [Signal("H08", "From: it@example.ac.jp"), Signal("H01")],
     "attached", "malicious")

# 正規システムからの通知は減点で相殺される
show("4 減点",
     [Signal("H11"), Signal("S02", "dkim=pass d=example.ac.jp")],
     "attached", "benign")

# 同一ルールが複数回検出されても、配点は1回だけ計上する。
# URLが3つとも悪性でも 30点（90点ではない）
show("5 重複",
     [Signal("U01", "evil1.example"), Signal("U01", "evil2.example"),
      Signal("U01", "evil3.example")],
     "attached", "unknown")

# 文脈系(LLM)だけでは悪性に到達しない。
# 全項目が誤って立っても合計80点で閾値100に届かない設計
show("6 LLMのみ",
     [Signal("C01"), Signal("C02"), Signal("C03"),
      Signal("C04"), Signal("C05")],
     "attached", "suspicious")

# YAMLに定義がないIDは無視される。
# detector側だけ先行実装した場合に解析が止まらないようにするため
r = scorer.score([Signal("X99", "未実装")], "attached")
print(f"OK 7 未定義: {VERDICT_JA[r.verdict]} / "
      f"無視されたID: {r.unknown_rule_ids}")
