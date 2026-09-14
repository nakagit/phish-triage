# -*- coding: utf-8 -*-
"""
analyzer/api.py

不審メール解析API。uvicorn で常駐させる。
pull.py が受信サーバーから取得した報告メールを受け取り、解析して通知する。

解析パイプライン:
  parser           二重構造の分離（転送メール / 元メール）
  detector_header  H系シグナル（認証、差出人の整合性）
  detector_url     U系シグナル（類似ドメイン、リンク偽装）
  detector_attach  A系シグナル（実行可能形式、マクロ、拡張子偽装）
  enrich           脅威インテリ照会（U01/A01/H09/H15）
  llm              C系シグナル（本文の文脈）
  scoring          ルールに基づく判定
  reporter         報告者向け / 担当者向け / IOC

設計上の原則:
  - 検体は「何があっても失わない」。解析コードのバグでメールを
    失うのが最悪のパターンなので、受理したら真っ先に保存する。
  - 保存が成功した時点で 202 を返す。解析の成否は返り値に含めない。
    pull.py は「解析APIが検体を受け取った」ことだけを確認して ack する。
  - シャドーモード中は通知を送らない。運用開始直後は実データで
    誤検知の傾向を掴んでから通知を有効化する。
  - 解析中の例外でプロセスを落とさない。判定不能として記録し、
    担当者の手動解析に回す。
  - 外部依存（脅威インテリ / LLM）が落ちても解析は続ける。ただし
    「該当なし」と「判定できなかった」を区別して記録する。

設定は config.yaml に集約している。systemd の Environment= で
個別に上書きすると二重管理になり、「設定を変えたのに反映されない」
という混乱を生むため、環境変数での上書きは一時的な用途に限ること。

起動例:
    cd analyzer
    python3 -m uvicorn api:app --host 127.0.0.1 --port 8081
"""
from __future__ import annotations

import json
import logging
import os
import sys
import traceback
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from fastapi import BackgroundTasks, FastAPI, Header, Request, Response

# 同一ディレクトリのモジュールを確実に読めるようにする。
# uvicorn の起動方法によっては cwd が異なるため、
# このファイルの位置を基準にする
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import cfg
from parser import parse_report
import detector_header as dh
import detector_url as du
import detector_attach as da
import enrich
import llm
import reporter
from scoring import Scorer, VERDICT_JA

JST = timezone(timedelta(hours=9))

# ---- 設定 ----
SPOOL = Path(cfg.get("spool.path"))

# シャドーモード。True の間は通知を送らず、記録だけ行う。
# 運用開始から最低2週間はこのままにして、判定精度を確認すること
SHADOW_MODE = bool(cfg.get("notify.shadow_mode"))

# 判定結果の送信先。通知の分岐やメール送信は受け取った側で行う
NOTIFY_WEBHOOK = cfg.get("notify.webhook")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("phish-api")

app = FastAPI(title="Phishing Triage API")

# Scorer は起動時に1回だけ読み込む。
# YAML の検証もここで走るので、設定不備があれば起動に失敗する（意図的）
scorer = Scorer(cfg.get("rules.path"))

log.info("設定ファイル: %s", cfg.path or "(なし。既定値を使用)")
log.info("ルール %d 件を読み込みました（組織ドメイン: %s）",
         len(scorer.rules), scorer.org_domains)

if SHADOW_MODE:
    log.warning("シャドーモードで起動しました。通知は送信されません")

if enrich.OPENCTI_URL and enrich.OPENCTI_TOKEN:
    log.info("脅威インテリ照合が有効です（スコア閾値: %d 超）",
             enrich.MIN_SCORE)
else:
    log.warning("脅威インテリが未設定です。U01/A01/H09/H15 は検出されません")

if llm.ENABLED:
    log.info("LLM 文脈判定が有効です（%s / %s）", llm.LLM_MODEL, llm.LLM_URL)
else:
    log.warning("LLM 判定が無効です。C01〜C05 は検出されません")


# ----------------------------------------------------------------------
# ユーティリティ
# ----------------------------------------------------------------------

def _job_id() -> str:
    """
    ジョブID を生成する。
    日時プレフィックスを付けることで、ディレクトリを ls しただけで
    時系列に並び、後から追跡しやすくなる
    """
    ts = datetime.now(JST).strftime("%Y%m%d-%H%M%S")
    return f"{ts}-{uuid.uuid4().hex[:8]}"


def _save(path: Path, data: bytes) -> None:
    """
    検体をディスクへ保存する。

    実行ビットは絶対に立てない。悪意あるファイルを扱うため、
    誤って実行される経路を作らない
    """
    path.write_bytes(data)
    os.chmod(path, 0o600)


def _notify(payload: dict) -> None:
    """
    判定結果を通知先へ送る。

    シャドーモード中は送らない。
    通知の失敗で解析結果を失わないよう、例外は握って記録するだけにする
    """
    if SHADOW_MODE:
        log.info("[シャドーモード] 通知をスキップしました: %s",
                 payload.get("verdict"))
        return

    if not NOTIFY_WEBHOOK:
        log.warning("notify.webhook が未設定です。通知を送れません")
        return

    try:
        resp = requests.post(NOTIFY_WEBHOOK, json=payload, timeout=10)
        resp.raise_for_status()
        log.info("通知を送信しました: %s", payload.get("verdict"))
    except Exception as e:
        # 通知に失敗しても結果はディスクに残っているので、後から再送できる
        log.error("通知の送信に失敗しました: %s", e)


# ----------------------------------------------------------------------
# 解析本体
# ----------------------------------------------------------------------

def analyze_job(job_id: str, raw: bytes, source_file: str) -> None:
    """
    バックグラウンドで解析を実行する。

    ここで例外が出ても、検体は既に保存済みなので失われない。
    エラーは result.json に記録し、担当者の手動解析に回す。
    """
    result_path = SPOOL / f"{job_id}.result.json"

    try:
        report = parse_report(raw)

        # 元メールのみを別ファイルとして保存する。
        # 手動解析や再解析のときに、内側だけを扱いたい場面が多い
        _save(SPOOL / f"{job_id}.original.eml", report.inner.as_bytes())

        # ---- 検出 ----
        # 報告者自身のなりすまし確認。判定スコアとは別枠で扱う
        reporter_warnings = dh.check_reporter(report)

        # ヘッダー系
        signals = dh.detect(report, scorer.org_domains)

        # URL系
        url_result = du.detect(report, scorer.org_domains)
        signals += url_result.signals

        # 添付系
        attach_result = da.detect(report)
        signals += attach_result.signals

        # 脅威インテリとの突き合わせ。
        # 照会に失敗しても解析は止めない。available=False で続行し、
        # 「ヒットなし」と「照会できなかった」をレポートで区別する
        enrich_result = enrich.enrich(
            report, url_result, attach_result, scorer.org_domains
        )
        signals += enrich_result.signals

        # 本文の文脈判定（ローカルLLM）。
        # LLM が落ちていても解析は止めない。
        # 配点設計上、C系は単独で悪性判定に到達しない
        llm_result = llm.detect(report)
        signals += llm_result.signals

        # ---- 判定 ----
        result = scorer.score(signals, mode=report.mode)

        # ---- レポート生成 ----
        rep = reporter.build(
            report, result, url_result, attach_result, reporter_warnings
        )

        payload = {
            "job_id": job_id,
            "source_file": source_file,
            "analyzed_at": datetime.now(JST).isoformat(),
            "shadow_mode": SHADOW_MODE,
            "reporter": report.reporter,
            "mode": report.mode,
            "subject": str(report.inner.get("Subject") or ""),
            # 判定結果（scoring.Result.to_dict）
            **result.to_dict(),
            "reporter_warnings": reporter_warnings,
            # 通知用の文面
            "user_subject": rep.subject_user,
            "user_body": rep.body_user,
            "soc_subject": rep.subject_soc,
            "soc_body": rep.body_soc,
            # 脅威インテリ投入用
            "iocs": rep.iocs,
            # 照会の記録。後から追跡できるようにしておく
            "enrich": {
                "available": enrich_result.available,
                "queried": enrich_result.queried,
                "hits": enrich_result.hits,
                "error": enrich_result.error,
            },
            # LLM 判定の記録。チューニングのため生の応答も残す
            "llm": {
                "available": llm_result.available,
                "model": llm.LLM_MODEL,
                "raw": llm_result.raw,
                "elapsed": round(llm_result.elapsed, 2),
                "error": llm_result.error,
            },
        }

        log.info(
            "解析完了 %s: %s (%s) 報告者=%s / CTI照会=%d件 ヒット=%d件 / LLM=%s",
            job_id, VERDICT_JA[result.verdict],
            "即時" if result.is_instant else f"{result.score}点",
            report.reporter,
            enrich_result.queried, len(enrich_result.hits),
            f"{len(llm_result.signals)}件" if llm_result.available else "判定不能",
        )

        # 外部依存が失敗した場合は警告を出す。
        # 「該当なし」と誤認したまま運用を続けるのを防ぐ
        if not enrich_result.available and enrich_result.error:
            log.warning("CTI照会にエラー %s: %s", job_id, enrich_result.error)
        if not llm_result.available and llm_result.error:
            log.warning("LLM判定にエラー %s: %s", job_id, llm_result.error)

    except Exception as e:
        # 解析に失敗しても検体は残っている。
        # 判定不能として記録し、担当者が手動で見られるようにする
        log.error("解析に失敗しました %s: %s", job_id, e)
        payload = {
            "job_id": job_id,
            "source_file": source_file,
            "analyzed_at": datetime.now(JST).isoformat(),
            "shadow_mode": SHADOW_MODE,
            "verdict": "unknown",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "soc_subject": f"[解析エラー] {job_id}",
            "soc_body": (
                f"解析中にエラーが発生しました。\n\n"
                f"ジョブID: {job_id}\n"
                f"検体: {SPOOL}/{job_id}.report.eml\n\n"
                f"{traceback.format_exc()}"
            ),
        }

    # 結果は成否にかかわらず必ず保存する
    try:
        result_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.chmod(result_path, 0o600)
    except Exception as e:
        log.error("結果の保存に失敗しました %s: %s", job_id, e)

    _notify(payload)


# ----------------------------------------------------------------------
# エンドポイント
# ----------------------------------------------------------------------

@app.post("/ingest/mail", status_code=202)
async def ingest_mail(
    request: Request,
    background: BackgroundTasks,
    x_source_file: str = Header(default=""),
):
    """
    報告メールを受け取る。

    保存が成功した時点で 202 を返し、解析はバックグラウンドで行う。
    呼び出し側はこの応答を見て ack するので、
    「保存できた = メールを失わない」ことが応答の意味になる。
    """
    raw = await request.body()

    if not raw:
        return Response(content='{"error":"empty body"}',
                        status_code=400, media_type="application/json")

    job_id = _job_id()

    # 真っ先に保存する。これが最優先。
    # ここで失敗したら 500 を返し、呼び出し側に ack させない
    try:
        SPOOL.mkdir(parents=True, exist_ok=True)
        _save(SPOOL / f"{job_id}.report.eml", raw)
    except Exception as e:
        log.error("検体の保存に失敗しました: %s", e)
        return Response(
            content=json.dumps({"error": f"save failed: {e}"}),
            status_code=500, media_type="application/json",
        )

    log.info("受理 %s: %d バイト (source=%s)", job_id, len(raw), x_source_file)

    # 解析は非同期。呼び出し側を待たせない
    background.add_task(analyze_job, job_id, raw, x_source_file)

    return {"job_id": job_id, "status": "accepted", "size": len(raw)}


@app.get("/health")
async def health():
    """死活監視用。systemd や外形監視から叩く"""
    return {
        "status": "ok",
        "config": cfg.path or None,
        "shadow_mode": SHADOW_MODE,
        "rules": len(scorer.rules),
        "spool": str(SPOOL),
        "spool_writable": os.access(SPOOL, os.W_OK),
        "opencti": bool(enrich.OPENCTI_URL and enrich.OPENCTI_TOKEN),
        "opencti_min_score": enrich.MIN_SCORE,
        "llm_enabled": llm.ENABLED,
        "llm_model": llm.LLM_MODEL,
    }


@app.get("/results/{job_id}")
async def get_result(job_id: str):
    """
    解析結果を取得する。

    job_id にパス区切りが含まれていないか必ず検証する。
    これを怠るとディレクトリトラバーサルで任意ファイルを読まれる
    """
    if "/" in job_id or ".." in job_id or not job_id:
        return Response(content='{"error":"invalid job_id"}',
                        status_code=400, media_type="application/json")

    path = SPOOL / f"{job_id}.result.json"
    if not path.exists():
        return Response(content='{"error":"not found"}',
                        status_code=404, media_type="application/json")

    return Response(content=path.read_text(encoding="utf-8"),
                    media_type="application/json")


@app.post("/reanalyze/{job_id}")
async def reanalyze(job_id: str, background: BackgroundTasks):
    """
    保存済みの検体を再解析する。

    配点や検出ロジックを変更した後、過去の報告を新しいルールで
    再評価するために使う。実運用のチューニングで頻繁に使うことになる。
    """
    if "/" in job_id or ".." in job_id or not job_id:
        return Response(content='{"error":"invalid job_id"}',
                        status_code=400, media_type="application/json")

    path = SPOOL / f"{job_id}.report.eml"
    if not path.exists():
        return Response(content='{"error":"not found"}',
                        status_code=404, media_type="application/json")

    background.add_task(analyze_job, job_id, path.read_bytes(), "reanalyze")
    return {"job_id": job_id, "status": "queued"}
