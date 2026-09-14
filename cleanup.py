#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/opt/phish/cleanup.py

スプール内の検体を判定に応じて世代管理する。

方針:
  - 悪性・疑わしい: 長期保管。インシデントの証跡として価値がある
  - 判定不能: 中期。後から手動解析する可能性がある
  - 問題なし: 短期。保管する意味が薄く、容量を圧迫するだけ
  - result.json がない: 削除しない。解析が失敗した可能性があり、
    人が確認するまで残す

削除は .report.eml / .original.eml / .result.json をセットで行う。
"""
import json
import logging
import os
import sys
import time
from pathlib import Path

SPOOL = Path(os.environ.get("PHISH_SPOOL", "/var/spool/phish"))

# 判定ごとの保持日数。
# 証跡の保持期間は法務・監査の要件によるため、必要なら調整すること
RETENTION_DAYS = {
    "malicious": 365,
    "suspicious": 365,
    "unknown": 180,
    "benign": 30,
}

# result.json が存在しないジョブの扱い。
# 解析に失敗した可能性があるため、長めに残して人の確認を待つ
NO_RESULT_DAYS = 180

log = logging.getLogger("phish-cleanup")


def verdict_of(job_id: str) -> str | None:
    """result.json から判定を読む。無ければ None"""
    path = SPOOL / f"{job_id}.result.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("verdict")
    except Exception as e:
        log.warning("result.json を読めません %s: %s", job_id, e)
        return None


def main() -> int:
    if not SPOOL.is_dir():
        log.error("スプールがありません: %s", SPOOL)
        return 1

    now = time.time()
    deleted = 0
    kept: dict[str, int] = {}
    freed = 0

    # .report.eml を基準にジョブを列挙する
    for report in sorted(SPOOL.glob("*.report.eml")):
        job_id = report.name[: -len(".report.eml")]

        verdict = verdict_of(job_id)
        if verdict is None:
            days = NO_RESULT_DAYS
            label = "解析結果なし"
        else:
            days = RETENTION_DAYS.get(verdict, NO_RESULT_DAYS)
            label = verdict

        age_days = (now - report.stat().st_mtime) / 86400

        if age_days < days:
            kept[label] = kept.get(label, 0) + 1
            continue

        # 関連ファイルをまとめて削除する
        for suffix in (".report.eml", ".original.eml", ".result.json"):
            target = SPOOL / f"{job_id}{suffix}"
            try:
                if target.exists():
                    freed += target.stat().st_size
                target.unlink(missing_ok=True)
            except Exception as e:
                log.error("削除に失敗 %s: %s", target, e)

        log.info("削除: %s (%s, %.0f日経過)", job_id, label, age_days)
        deleted += 1

    summary = ", ".join(f"{k}:{v}" for k, v in sorted(kept.items()))
    log.info("完了。削除 %d 件 / %.1f MB 解放 / 保持 %s",
             deleted, freed / 1024 / 1024, summary or "なし")
    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    sys.exit(main())
