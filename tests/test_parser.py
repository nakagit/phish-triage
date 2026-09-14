# -*- coding: utf-8 -*-
"""
tests/test_parser.py

転送メールの二重構造が正しく分離できるか確認する。

    python3 tests/test_parser.py <検体.eml>

確認すべき点:
  - mode が attached か inline か
  - 内側の From が元メールの差出人になっているか
  - 内側の認証結果（報告者の受信サーバーが付けたもの）が取れているか

内側の認証結果が取れていないと、判定の最重要材料が失われる。
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

from parser import (parse_report, get_addr, domain_of,
                    get_auth_results, get_received_chain)

if len(sys.argv) < 2:
    print("使い方: python3 tests/test_parser.py <検体.eml>", file=sys.stderr)
    sys.exit(2)

with open(sys.argv[1], "rb") as f:
    raw = f.read()

r = parse_report(raw)

print(f"mode          : {r.mode}")
print(f"報告者        : {r.reporter}")
print(f"外側の認証結果: {r.outer_auth[:80] if r.outer_auth else '(なし)'}")
print()
print("--- 内側（判定対象）---")
print(f"件名     : {r.inner.get('Subject')}")

name, addr = get_addr(r.inner, "From")
print(f"From     : 表示名='{name}' アドレス='{addr}' "
      f"ドメイン='{domain_of(addr)}'")

_, rp = get_addr(r.inner, "Return-Path")
print(f"Return-Path : {rp} (ドメイン: {domain_of(rp)})")

_, rt = get_addr(r.inner, "Reply-To")
print(f"Reply-To    : {rt or '(なし)'}")

auth = get_auth_results(r.inner)
print(f"認証結果 : {len(auth)} 件")
for a in auth:
    print(f"  - {a[:100]}")

print(f"Received : {len(get_received_chain(r.inner))} ホップ")

if r.warnings:
    print()
    print("警告:")
    for w in r.warnings:
        print(f"  - {w}")
