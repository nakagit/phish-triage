# -*- coding: utf-8 -*-
"""
tests/test_report.py

レポート生成の確認。報告者向け・担当者向け・IOC を表示する。

    python3 tests/test_report.py <検体.eml>

確認すべき点:
  - 判定に応じて断定の強さが変わっているか
  - URLが無害化されているか（hxxps:// と [.]）
  - 改行や罫線が崩れていないか
  - 正常判定でも「安全を保証しない」旨が入っているか
"""
import json
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
import reporter
from scoring import Scorer

if len(sys.argv) < 2:
    print("使い方: python3 tests/test_report.py <検体.eml>", file=sys.stderr)
    sys.exit(2)

scorer = Scorer()

with open(sys.argv[1], "rb") as f:
    report = parse_report(f.read())

warnings = dh.check_reporter(report)

signals = dh.detect(report, scorer.org_domains)
url_result = du.detect(report, scorer.org_domains)
signals += url_result.signals
attach_result = da.detect(report)
signals += attach_result.signals

result = scorer.score(signals, mode=report.mode)
rep = reporter.build(report, result, url_result, attach_result, warnings)

print("#" * 60)
print("# 報告者向け")
print("#" * 60)
print(f"件名: {rep.subject_user}")
print()
print(rep.body_user)
print()
print("#" * 60)
print("# 担当者向け")
print("#" * 60)
print(f"件名: {rep.subject_soc}")
print()
print(rep.body_soc)
print()
print("#" * 60)
print("# IOC")
print("#" * 60)
print(json.dumps(rep.iocs, ensure_ascii=False, indent=2))
