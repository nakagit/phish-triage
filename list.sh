#!/bin/bash
# 解析結果の一覧を表示する。日次の確認用。
#
# シャドーモード期間中、この出力を眺めて誤判定がないか確認する。
# 判定を疑ったら、対応する .report.eml を samples/ に加えて回帰テストの資産にする。

SPOOL="${PHISH_SPOOL:-/var/spool/phish}"

shopt -s nullglob

found=0
for f in "$SPOOL"/*.result.json; do
    found=1
    python3 -c "
import json, sys
try:
    d = json.load(open('$f'))
except Exception as e:
    print(f'  [読み込み失敗] $f ({e})')
    sys.exit()

# 即時確定はスコアを持たないので表示を分ける
score = '即時' if d.get('instant') else str(d.get('score', '-'))

# 判定を日本語で表示する
ja = {'malicious':'悪性', 'suspicious':'疑わしい',
      'unknown':'判定不能', 'benign':'問題なし'}
verdict = ja.get(d.get('verdict', ''), d.get('verdict', '?'))

# エラーで解析できなかったものは明示する
if d.get('error'):
    verdict = '解析エラー'

print(f\"{d.get('job_id','?')}  {verdict:8s} {score:>4s}  \"
      f\"{d.get('mode','?'):8s}  {d.get('subject','')[:40]}\")
"
done

if [ "$found" -eq 0 ]; then
    echo "解析結果がありません: $SPOOL"
fi
