#!/bin/bash
# phish-triage の死活を確認する。
#
# 確認項目:
#   1. 解析APIが応答するか
#   2. pull のタイマーが動いているか
#   3. 受信サーバー側に未処理メールが滞留していないか
#   4. ディスクに余裕があるか
#
# 異常があれば syslog にエラーとして記録し、
# PHISH_ALERT_WEBHOOK が設定されていれば通知を送る。
#
# 正常時は PHISH_HEARTBEAT_URL へ ping する。
# 内部の監視はシステムごと落ちると通知も飛ばないため、
# 外形監視サービスへのハートビートが実質的な最後の砦になる。
#
# systemd timer から定期実行する想定。
# 異常検知時は終了コード1を返すので、
# systemctl list-units --failed でも把握できる。

set -uo pipefail

# ---- 設定 ----
# 接続先は config.yaml から読む。設定を1箇所に集約するため。
# 環境変数で上書きもできる
ANALYZER_DIR="${PHISH_ANALYZER_DIR:-/opt/phish/analyzer}"

SSH_TARGET=""
SSH_KEY=""
SPOOL="/var/spool/phish"

if [ -d "$ANALYZER_DIR" ]; then
    read -r SSH_TARGET SSH_KEY SPOOL < <(python3 -c "
import sys
sys.path.insert(0, '$ANALYZER_DIR')
from config import cfg
print(cfg.get('pull.ssh_target') or '-',
      cfg.get('pull.ssh_key') or '-',
      cfg.get('spool.path') or '/var/spool/phish')
" 2>/dev/null) || true
fi

# config から読めなかった場合の既定値
[ -z "${SPOOL:-}" ] || [ "$SPOOL" = "-" ] && SPOOL="/var/spool/phish"

API_URL="${PHISH_HEALTH_API:-http://127.0.0.1:8081/health}"
PULL_TIMER="${PHISH_PULL_TIMER:-phish-pull.timer}"

# 未処理メールの滞留とみなす件数。
# pull は1分間隔で動くので、複数件残っていれば取得が止まっている
PENDING_THRESHOLD="${PHISH_PENDING_THRESHOLD:-5}"

# ディスク使用率の警告閾値。
# 余裕があるうちに気づけるよう、満杯になる前に警告する
DISK_THRESHOLD="${PHISH_DISK_THRESHOLD:-85}"

problems=()
pending=0
usage=0

# ================================================================
# 1. 解析APIの応答
# ================================================================
if ! curl -sf --max-time 5 "$API_URL" > /dev/null; then
    problems+=("解析APIが応答しません ($API_URL)")
fi

# ================================================================
# 2. pull タイマーの稼働
# ================================================================
if systemctl list-unit-files "$PULL_TIMER" >/dev/null 2>&1; then
    if ! systemctl is-active --quiet "$PULL_TIMER"; then
        problems+=("$PULL_TIMER が停止しています")
    fi
fi

# ================================================================
# 3. 受信サーバー側の滞留
# ================================================================
# pull が止まっていると未処理メールが溜まり続ける。
# SSH 自体が失敗した場合も検知したいので、終了コードを見る
if [ -n "$SSH_TARGET" ] && [ "$SSH_TARGET" != "-" ] \
   && [ -n "$SSH_KEY" ] && [ "$SSH_KEY" != "-" ]; then
    if pending=$(ssh -i "$SSH_KEY" \
                     -o BatchMode=yes \
                     -o StrictHostKeyChecking=yes \
                     -o ConnectTimeout=10 \
                     "$SSH_TARGET" list 2>/dev/null | wc -l); then
        if [ "$pending" -gt "$PENDING_THRESHOLD" ]; then
            problems+=("受信サーバーに未処理メールが ${pending} 件滞留しています")
        fi
    else
        problems+=("受信サーバーへの SSH 接続に失敗しました")
        pending=0
    fi
fi

# ================================================================
# 4. ディスク使用率
# ================================================================
usage=$(df --output=pcent "$SPOOL" 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "$usage" ] && [ "$usage" -gt "$DISK_THRESHOLD" ]; then
    problems+=("ディスク使用率が ${usage}% です ($SPOOL)")
fi

# ================================================================
# 結果
# ================================================================
if [ ${#problems[@]} -eq 0 ]; then
    logger -t phish-health "OK (未処理 ${pending} 件, ディスク ${usage}%)"

    # 外形監視へのハートビート。
    # これが途絶えると監視サービス側から通知が飛ぶ。
    # システムごと落ちた場合でも気づける唯一の手段
    if [ -n "${PHISH_HEARTBEAT_URL:-}" ]; then
        curl -sf --max-time 10 "$PHISH_HEARTBEAT_URL" > /dev/null || true
    fi
    exit 0
fi

message="phish-triage に異常があります:"
for p in "${problems[@]}"; do
    message="${message}"$'\n'"  - ${p}"
done

logger -t phish-health -p user.err "$message"
echo "$message" >&2

# 通知先が設定されていれば送る。
# 通知の失敗でスクリプト自体が落ちないよう || true を付ける
if [ -n "${PHISH_ALERT_WEBHOOK:-}" ]; then
    payload=$(python3 -c "
import json, sys
print(json.dumps({'text': sys.stdin.read()}))
" <<< "$message")
    curl -sf --max-time 10 -X POST "$PHISH_ALERT_WEBHOOK" \
         -H "Content-Type: application/json" \
         -d "$payload" > /dev/null || true
fi

exit 1
