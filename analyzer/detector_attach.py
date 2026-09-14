# -*- coding: utf-8 -*-
"""
/opt/phish/analyzer/detector_attach.py

添付ファイル系シグナル(A02〜A08)の検出。

このモジュールは「悪意あるファイルを直接扱う」層である。
以下の安全原則を必ず守ること:

  1. 添付を実行しない・開かない。バイト列として読むだけ。
  2. 展開は深度とサイズに上限を設ける(zip爆弾対策)。
  3. パーサ自体が攻撃対象になり得るため、全ての解析を例外で囲む。
     1つの添付の解析失敗が、メール全体の判定を止めてはいけない。
  4. ディスクに書き出す場合は実行ビットを立てない。
  5. 外部通信はしない。ハッシュ照合(A01)は enrich.py に分離する。

運用上の注意:
  解析サーバー上のアンチウイルスが検体を勝手に隔離すると解析不能になる。
  スプールディレクトリをAV除外に設定したうえで、必要なら ClamAV を
  「検出するが削除しない」モードで明示的に呼ぶ構成にすること。
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from email.message import EmailMessage

from parser import ParsedReport
from scoring import Signal

log = logging.getLogger(__name__)

# python-magic はインストールされていない環境もあり得るため、
# 無くても他の検出は動くようにする
try:
    import magic as _magic
    _HAS_MAGIC = True
except Exception:  # pragma: no cover
    _HAS_MAGIC = False
    log.warning("python-magic が利用できません。A03(拡張子偽装)は無効になります")

try:
    from oletools.olevba import VBA_Parser
    _HAS_OLETOOLS = True
except Exception:  # pragma: no cover
    _HAS_OLETOOLS = False
    log.warning("oletools が利用できません。A02(マクロ検出)は無効になります")


# ---- 安全上の上限値 ----
# 1添付あたりの解析対象サイズ。これを超える分は読まない
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024        # 25MB
# アーカイブ展開後の合計サイズ上限(zip爆弾対策)
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024     # 100MB
# アーカイブの入れ子の深さ上限
MAX_ARCHIVE_DEPTH = 2
# アーカイブ内で検査するエントリ数の上限
MAX_ARCHIVE_ENTRIES = 200

# 実行可能形式の拡張子(A07)。
# 開いた瞬間にコードが動くもの、およびそれを起動できるもの
EXECUTABLE_EXTS = {
    "exe", "com", "scr", "pif", "cpl", "msi", "msp", "mst",
    "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ws",
    "ps1", "psm1", "hta", "lnk", "url", "reg", "inf", "jar",
    "app", "dmg", "pkg", "deb", "rpm", "sh", "run", "bin",
    "iso", "img", "vhd",   # マウントされて中身が実行される
}

# 二重拡張子(A08)の判定に使う、文書に見せかけるための拡張子
DOCUMENT_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "mp4", "zip",
}

# アーカイブの拡張子
ARCHIVE_EXTS = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "ace"}

# 拡張子と、magic が返すべき MIME タイプの対応(A03)。
# 完全一致ではなく「この拡張子ならこのMIMEのいずれか」という許容リスト
EXT_MIME_MAP: dict[str, set[str]] = {
    "pdf":  {"application/pdf"},
    "zip":  {"application/zip", "application/java-archive"},
    "docx": {"application/zip",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xlsx": {"application/zip",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "pptx": {"application/zip",
             "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    "doc":  {"application/msword", "application/vnd.ms-office",
             "application/x-ole-storage", "application/CDFV2"},
    "xls":  {"application/vnd.ms-excel", "application/vnd.ms-office",
             "application/x-ole-storage", "application/CDFV2"},
    "jpg":  {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "png":  {"image/png"},
    "gif":  {"image/gif"},
    "txt":  {"text/plain"},
    "html": {"text/html"},
    "htm":  {"text/html"},
}

# PDF内のJavaScriptや自動実行を示すキーワード(A05)。
# PDF仕様上の辞書キーで、正規のPDFにはまず現れない
PDF_DANGEROUS_KEYS = [
    b"/JavaScript", b"/JS", b"/OpenAction", b"/AA",
    b"/Launch", b"/EmbeddedFile", b"/RichMedia",
]


@dataclass
class Attachment:
    """添付ファイル1件"""
    filename: str
    content_type: str
    size: int
    sha256: str
    ext: str = ""                  # 小文字の拡張子(ドットなし)
    detected_mime: str = ""        # magic による判定結果
    inner_files: list[str] = field(default_factory=list)   # アーカイブ内のファイル名
    error: str = ""                # 解析中のエラー


@dataclass
class AttachAnalysis:
    attachments: list[Attachment] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)


# ----------------------------------------------------------------------
# 添付の抽出
# ----------------------------------------------------------------------

def _get_ext(filename: str) -> str:
    """ファイル名から拡張子を取り出す(小文字、ドットなし)"""
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower().strip()


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    """
    メールから添付ファイルを取り出す。

    本文(text/plain, text/html でインライン表示されるもの)は対象外。
    ただし HTML が添付として付いている場合は対象に含める(A04の検出対象)。
    """
    results: list[Attachment] = []

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        disposition = part.get_content_disposition()
        filename = part.get_filename() or ""

        # 添付と判定する条件:
        #   - Content-Disposition: attachment が付いている
        #   - または filename が指定されている(inline画像なども含む)
        if disposition != "attachment" and not filename:
            continue

        try:
            payload = part.get_payload(decode=True)
        except Exception as e:
            log.warning("添付のデコードに失敗: %s (%s)", filename, e)
            results.append(Attachment(
                filename=filename or "(名前なし)",
                content_type=part.get_content_type(),
                size=0, sha256="", error=f"デコード失敗: {e}",
            ))
            continue

        if payload is None:
            continue

        size = len(payload)

        # 巨大な添付は解析対象外。ハッシュだけ取って記録する。
        # メモリを食い潰して解析基盤ごと落ちるのを防ぐ
        if size > MAX_ATTACHMENT_SIZE:
            results.append(Attachment(
                filename=filename or "(名前なし)",
                content_type=part.get_content_type(),
                size=size,
                sha256=hashlib.sha256(payload).hexdigest(),
                ext=_get_ext(filename),
                error=f"サイズ上限({MAX_ATTACHMENT_SIZE}バイト)超過のため解析を省略",
            ))
            continue

        att = Attachment(
            filename=filename or "(名前なし)",
            content_type=part.get_content_type(),
            size=size,
            sha256=hashlib.sha256(payload).hexdigest(),
            ext=_get_ext(filename),
        )

        # magic によるファイル種別判定。
        # 拡張子偽装(A03)の検出に使う
        if _HAS_MAGIC:
            try:
                att.detected_mime = _magic.from_buffer(payload, mime=True)
            except Exception as e:
                log.warning("magic 判定に失敗: %s (%s)", filename, e)

        # 解析用にペイロードを一時的に保持する。
        # Attachment に持たせるとレポート生成まで引きずるため、別辞書で管理
        _payload_cache[att.sha256] = payload

        results.append(att)

    return results


# 解析中だけペイロードを保持する。detect() の最後で必ず破棄する
_payload_cache: dict[str, bytes] = {}


# ----------------------------------------------------------------------
# 個別の解析
# ----------------------------------------------------------------------

def _has_macro(payload: bytes, filename: str) -> tuple[bool, str]:
    """
    Office文書にVBAマクロが含まれているか判定する(A02)。

    oletools の VBA_Parser を使う。このパーサ自体が攻撃対象になり得るため、
    必ず例外で囲む。失敗しても解析全体は止めない。
    """
    if not _HAS_OLETOOLS:
        return False, ""

    try:
        # data= でバイト列を直接渡す。ディスクに書き出さない
        parser = VBA_Parser(filename, data=payload)
        try:
            if not parser.detect_vba_macros():
                return False, ""

            # マクロの中身から危険なキーワードを抽出する。
            # Auto_Open などは開いた瞬間に実行される
            keywords: list[str] = []
            for _, _, _, code in parser.extract_macros():
                for kw in ("Auto_Open", "AutoOpen", "Document_Open",
                           "Workbook_Open", "Shell", "CreateObject",
                           "WScript", "PowerShell", "URLDownloadToFile"):
                    if kw.lower() in (code or "").lower() and kw not in keywords:
                        keywords.append(kw)

            detail = f"マクロ検出: {', '.join(keywords)}" if keywords else "マクロ検出"
            return True, detail
        finally:
            parser.close()
    except Exception as e:
        log.warning("マクロ解析に失敗: %s (%s)", filename, e)
        return False, ""


def _pdf_has_active_content(payload: bytes) -> tuple[bool, str]:
    """
    PDF内にJavaScriptや自動実行アクションが含まれるか判定する(A05)。

    pdfid 相当の処理を自前で行う。外部のPDFパーサを使わないのは、
    パーサ自体の脆弱性を経由した攻撃を避けるため。
    単純なバイト列検索なので、悪意あるPDFを「解釈」しない。
    """
    found: list[str] = []
    for key in PDF_DANGEROUS_KEYS:
        if key in payload:
            found.append(key.decode("ascii"))

    if found:
        return True, ", ".join(found)
    return False, ""


def _archive_info(payload: bytes, depth: int = 0) -> tuple[list[str], bool, str]:
    """
    アーカイブの中身を列挙する。

    展開はしない。エントリ名とサイズ情報だけを読む。
    zip爆弾対策として、展開後サイズの合計とエントリ数に上限を設ける。

    戻り値: (ファイル名リスト, パスワード保護されているか, エラー)
    """
    if depth > MAX_ARCHIVE_DEPTH:
        return [], False, "入れ子が深すぎるため解析を打ち切りました"

    names: list[str] = []
    encrypted = False

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            total = 0
            for i, info in enumerate(zf.infolist()):
                if i >= MAX_ARCHIVE_ENTRIES:
                    return names, encrypted, "エントリ数が多すぎるため打ち切りました"

                # flag_bits の 0x1 が立っていれば暗号化されている
                if info.flag_bits & 0x1:
                    encrypted = True

                total += info.file_size
                # 展開後の合計サイズが上限を超えたらzip爆弾とみなす
                if total > MAX_UNCOMPRESSED_SIZE:
                    return names, encrypted, (
                        f"展開後サイズが上限({MAX_UNCOMPRESSED_SIZE}バイト)を"
                        "超えます。zip爆弾の可能性があります"
                    )

                names.append(info.filename)
    except zipfile.BadZipFile:
        return [], False, "ZIPとして読めませんでした"
    except Exception as e:
        return [], False, f"アーカイブ解析エラー: {e}"

    return names, encrypted, ""


def _is_double_extension(filename: str) -> tuple[bool, str]:
    """
    二重拡張子を検出する(A08)。

    請求書.pdf.exe のように、文書に見せかけたプログラム。
    Windows が既定で拡張子を隠すため、.pdf に見えてしまう。

    また、Unicode の RLO(右から左へ上書き U+202E) による
    見た目の反転も検出する。これは exe.docx のように見せかける手口。
    """
    # RLO による拡張子偽装
    if "\u202e" in filename or "\u202d" in filename:
        return True, "Unicode制御文字(RLO)による拡張子偽装"

    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False, ""

    last = parts[-1]
    second_last = parts[-2]

    # 「文書っぽい拡張子」の後に「実行可能な拡張子」が続く場合
    if second_last in DOCUMENT_EXTS and last in EXECUTABLE_EXTS:
        return True, f".{second_last}.{last}"

    return False, ""


# ----------------------------------------------------------------------
# 検出本体
# ----------------------------------------------------------------------

def detect(report: ParsedReport) -> AttachAnalysis:
    """
    添付ファイル系のシグナルを検出する。

    A01(既知マルウェアハッシュ)は外部通信が必要なため、
    ここでは扱わない。sha256 は Attachment に入れてあるので、
    enrich.py がそれを使って照合する。
    """
    attachments = extract_attachments(report.inner)
    signals: list[Signal] = []

    try:
        for att in attachments:
            payload = _payload_cache.get(att.sha256)

            # ---- A08: 二重拡張子 ----
            # 最初に判定する。ファイル名だけで分かり、最も危険度が高い
            is_double, detail = _is_double_extension(att.filename)
            if is_double:
                signals.append(Signal("A08", f"{att.filename} ({detail})"))

            # ---- A07: 実行可能形式 ----
            if att.ext in EXECUTABLE_EXTS:
                signals.append(Signal("A07", f"{att.filename} (.{att.ext})"))

            # ---- A04: HTML添付 ----
            # ローカルに保存されて開かれる偽ログインページ。近年非常に多い
            if att.ext in ("html", "htm", "shtml", "mht", "mhtml"):
                signals.append(Signal("A04", att.filename))

            # ペイロードが無い場合(サイズ超過など)はここまで
            if payload is None:
                continue

            # ---- A03: 拡張子と実体の不一致 ----
            if att.ext and att.detected_mime:
                expected = EXT_MIME_MAP.get(att.ext)
                if expected and att.detected_mime not in expected:
                    signals.append(Signal(
                        "A03",
                        f"{att.filename}: 拡張子=.{att.ext} / "
                        f"実体={att.detected_mime}"
                    ))

            # ---- A02: Officeマクロ ----
            if att.ext in ("doc", "docm", "dot", "dotm", "xls", "xlsm",
                           "xlt", "xltm", "ppt", "pptm", "docx", "xlsx", "pptx"):
                has_macro, detail = _has_macro(payload, att.filename)
                if has_macro:
                    signals.append(Signal("A02", f"{att.filename}: {detail}"))

            # ---- A05: PDF内のアクティブコンテンツ ----
            if att.ext == "pdf" or att.detected_mime == "application/pdf":
                is_active, detail = _pdf_has_active_content(payload)
                if is_active:
                    signals.append(Signal("A05", f"{att.filename}: {detail}"))

            # ---- A06: パスワード付きアーカイブ ----
            if att.ext in ARCHIVE_EXTS or att.detected_mime == "application/zip":
                names, encrypted, err = _archive_info(payload)
                att.inner_files = names[:20]
                if err:
                    att.error = err
                    # zip爆弾の疑いはそれ自体が危険信号
                    if "爆弾" in err:
                        signals.append(Signal("A06", f"{att.filename}: {err}"))

                if encrypted:
                    signals.append(Signal(
                        "A06", f"{att.filename}: パスワード保護されています"
                    ))

                # アーカイブ内に実行可能ファイルがある場合も A07 相当
                for name in names:
                    inner_ext = _get_ext(name)
                    if inner_ext in EXECUTABLE_EXTS:
                        signals.append(Signal(
                            "A07", f"{att.filename} 内の {name} (.{inner_ext})"
                        ))
                        break   # 1アーカイブにつき1回

    finally:
        # ペイロードのキャッシュは必ず破棄する。
        # 悪意あるバイト列をプロセスに残し続けない
        _payload_cache.clear()

    return AttachAnalysis(attachments=attachments, signals=signals)
