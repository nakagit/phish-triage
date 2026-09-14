#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/opt/phish/pull.py

受信サーバーの Maildir から未処理の報告メールを取得し、解析APIへ渡す。
systemd timer から定期実行する。

設計方針:
  - 解析APIが確実に受理した後にのみ ack する。
    先に ack すると、API 障害時にメールを取りこぼす。
  - 1通の失敗が他の処理を止めないよう、例外は通ごとに握る。
  - 受信サーバー側には認証情報を一切持たせず、こちらから取りに行く(pull)。
    受信サーバーは公開MXであり最も攻撃を受けやすいため、
    そこが侵害されても内部への足がかりにならない構成にする。

受信サーバー側の準備:
  - 専用ユーザーの authorized_keys に command= を指定し、
    許可するコマンドを list / fetch / ack の3種に限定する
  - no-pty, no-port-forwarding, restrict を付けてシェルを取らせない
"""
import logging
import subprocess
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent / "analyzer"))

from config import cfg

SSH_TARGET = str(cfg.get("pull.ssh_target") or "")
SSH_KEY = str(cfg.get("pull.ssh_key") or "")
ANALYZE_API = str(cfg.get("pull.api_url") or "")

log = logging.getLogger("phish-pull")


def ssh(command: str) -> bytes:
    """
    受信サーバー側のゲートスクリプトにコマンドを1つ投げ、標準出力を返す。
    許可されているのは list / fetch <file> / ack <file> の3種類のみ。
    """
    result = subprocess.run(
        [
            "ssh", "-i", SSH_KEY,
            # 鍵認証のみ。パスワード入力待ちで固まるのを防ぐ
            "-o", "BatchMode=yes",
            # 中間者攻撃対策。known_hosts にない鍵は拒否する
            "-o", "StrictHostKeyChecking=yes",
            # 接続が無反応のまま滞留しないよう上限を設ける
            "-o", "ConnectTimeout=10",
            SSH_TARGET, command,
        ],
        check=True, capture_output=True, timeout=60,
    )
    return result.stdout


def process_one(name: str) -> None:
    """1通を取得し、解析APIへ渡し、成功したら ack する"""
    raw = ssh(f"fetch {name}")
    if not raw:
        # 空なら取得失敗。ack せずに残して次回再試行させる
        raise RuntimeError("empty response")

    resp = requests.post(
        ANALYZE_API,
        data=raw,
        headers={
            "Content-Type": "message/rfc822",
            # 受信サーバー側のファイル名を渡しておくと、後で突き合わせができる
            "X-Source-File": name,
        },
        timeout=30,
    )
    resp.raise_for_status()

    # 解析APIが 2xx を返した後にのみ ack する。
    # API は検体を保存した時点で 202 を返すので、
    # 「保存できた = メールを失わない」ことが確認できている
    ssh(f"ack {name}")
    log.info("processed: %s -> %s", name, resp.json().get("job_id"))


def main() -> int:
    if not (SSH_TARGET and SSH_KEY and ANALYZE_API):
        log.error("pull の設定が不足しています。config.yaml の "
                  "pull.ssh_target / ssh_key / api_url を確認してください")
        return 1

    try:
        filenames = ssh("list").decode().split()
    except Exception as e:
        log.error("list failed: %s", e)
        return 1

    if not filenames:
        return 0

    log.info("found %d message(s)", len(filenames))

    failed = 0
    for name in filenames:
        try:
            process_one(name)
        except Exception as e:
            # 失敗したものは ack しないので未処理のまま残り、次回再試行される
            log.error("failed: %s (%s)", name, e)
            failed += 1

    return 1 if failed else 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    sys.exit(main())
