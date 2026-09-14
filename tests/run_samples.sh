#!/bin/bash
# 全検体を一括で解析し、判定の変化を確認する。
# 配点や検出ロジックを変更したら必ず実行する。
#
# 検体は <リポジトリ>/samples/<分類>/*.eml に置く:
#   benign/    = 正常判定されるべきもの（誤検知の検出用）
#   gray/      = 判断が分かれるもの
#   malicious/ = 悪性判定されるべきもの（見逃しの検出用）
#
# 内容が同じ検体を2つ入れておくと、LLM の非決定性に気づける。
#
# 検体には実在のメールアドレスや第三者の通信内容が含まれるため、
# リポジトリにコミットしないこと（.gitignore で除外済み）。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

SAMPLE_DIR="${PHISH_SAMPLE_DIR:-$REPO_DIR/samples}"
TESTER="$SCRIPT_DIR/test_detector.py"

shopt -s nullglob

found=0
for f in "$SAMPLE_DIR"/*/*.eml; do
    found=1
    echo "=============================================="
    echo "検体: ${f#$SAMPLE_DIR/}"
    echo "----------------------------------------------"
    python3 "$TESTER" "$f" 2>&1
    echo
done

if [ "$found" -eq 0 ]; then
    echo "検体が見つかりません: $SAMPLE_DIR/*/*.eml"
    exit 1
fi
