# -*- coding: utf-8 -*-
"""
tests/test_detector.py

解析パイプライン全体を1通のメールに対して実行し、結果を表示する。

    python3 tests/test_detector.py <検体.eml>

配点や検出条件を変更したら run_samples.sh で全検体に対して実行し、
判定が意図通りに変化したかを確認する。

外部照会(enrich)と LLM 判定は含まない。
それらを含めた通しの確認は api.py 経由で行う。
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

from parser import parse_report
import detector_header as dh
import detector_url as du
import detector_attach as da
from scoring import Scorer, VERDICT_JA


def defang(url: str) -> str:
    """
    URLを無害化して表示する。
    ターミナルの自動リンク化による誤クリックを防ぐ
    """
    return url.replace("http", "hxxp", 1)


def main() -> int:
    if len(sys.argv) < 2:
        print("使い方: python3 tests/test_detector.py <検体.eml>",
              file=sys.stderr)
        return 2

    try:
        with open(sys.argv[1], "rb") as f:
            raw = f.read()
    except OSError as e:
        print(f"検体を読めません: {e}", file=sys.stderr)
        return 2

    scorer = Scorer()
    report = parse_report(raw)

    # ================================================================
    # 基本情報
    # ================================================================
    print(f"mode: {report.mode} / 報告者: {report.reporter}")
    print(f"件名: {report.inner.get('Subject')}")

    for w in report.warnings:
        print(f"[注意] {w}")
    print()

    # ================================================================
    # 報告者自身のなりすまし確認（判定スコアとは別枠）
    # ================================================================
    reporter_warnings = dh.check_reporter(report)
    for w in reporter_warnings:
        print(f"[報告者警告] {w}")
    if reporter_warnings:
        print()

    # ================================================================
    # 検出
    # ================================================================
    signals = []
    signals += dh.detect(report, scorer.org_domains)

    url_result = du.detect(report, scorer.org_domains)
    signals += url_result.signals

    attach_result = da.detect(report)
    signals += attach_result.signals

    # ================================================================
    # 抽出したURLの一覧
    # ================================================================
    if url_result.urls:
        print(f"--- 抽出URL: {len(url_result.urls)} 件 "
              f"（ホスト {len(url_result.unique_hosts)} 種）---")
        for u in url_result.urls[:10]:
            print(f"  [{u.source}] {defang(u.url)[:90]}")
            if u.anchor_text:
                print(f"        表示: {u.anchor_text[:60]}")
        if len(url_result.urls) > 10:
            print(f"  ...他 {len(url_result.urls) - 10} 件")
        print()
    else:
        print("--- 抽出URL: なし ---")
        print()

    # ================================================================
    # 添付ファイルの一覧
    # ================================================================
    if attach_result.attachments:
        print(f"--- 添付ファイル: {len(attach_result.attachments)} 件 ---")
        for a in attach_result.attachments:
            print(f"  {a.filename}")
            print(f"      種別: {a.content_type} / "
                  f"実体: {a.detected_mime or '不明'}")
            print(f"      サイズ: {a.size:,} バイト")
            print(f"      SHA256: {a.sha256}")
            if a.inner_files:
                print(f"      内容: {', '.join(a.inner_files[:5])}")
                if len(a.inner_files) > 5:
                    print(f"            ...他 "
                          f"{len(a.inner_files) - 5} 件")
            if a.error:
                print(f"      [エラー] {a.error}")
        print()
    else:
        print("--- 添付ファイル: なし ---")
        print()

    # ================================================================
    # 検出シグナル
    # ================================================================
    print(f"--- 検出シグナル: {len(signals)} 件 ---")
    if not signals:
        print("  （なし）")
    for s in signals:
        rule = scorer.rules.get(s.rule_id, {})
        score = rule.get("score")
        score_str = f"{score:+3}" if isinstance(score, int) else " ? "
        print(f"  {s.rule_id} ({score_str}) "
              f"{rule.get('label', '【YAML未定義】')}")
        if s.detail:
            print(f"        └ {s.detail}")

    # ================================================================
    # 判定
    # ================================================================
    result = scorer.score(signals, mode=report.mode)

    print()
    print(f"=== 判定: {VERDICT_JA[result.verdict]} ===")

    if result.is_instant:
        print(f"即時確定: {result.instant_reason}")
    else:
        print(f"スコア: {result.score} 点 "
              f"(悪性閾値: {result.threshold_malicious} / "
              f"疑わしい閾値: {result.threshold_suspicious})")

    print(f"確度: {result.confidence}")

    if result.unknown_rule_ids:
        print(f"[警告] YAML未定義のルールID: {result.unknown_rule_ids}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
