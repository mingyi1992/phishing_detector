"""圖片分析：QR Code 解碼與 OCR（全部在本機執行）。

圖片來源：信件中的 image/* 部分（內嵌或附件）、HTML 中的 data:image base64。
外部圖片（<img src="http://...">）不會下載（不連外），但「幾乎沒有文字、只有圖片」本身會被標記。

套件（選用，未安裝時該功能標示為「未分析」）：
  * QR Code：opencv-python-headless
  * OCR    ：rapidocr_onnxruntime（模型隨套件安裝，支援中英文，不需連網）
OCR 文字會送進 LLM 判讀、注入偵測與網址分析；QR Code 網址會送進網址分析。
"""
from __future__ import annotations

import base64
import binascii
import re

from .common import Finding
from .injection_guard import html_to_text, normalize
from .parser import ParsedEmail

M = "image"
_MAX_IMAGES = 10
_MAX_BYTES = 10 * 2**20
_MIN_BYTES = 1024           # 太小的多半是追蹤像素或圖示

_ocr_engine = None


def _cv2():
    try:
        import cv2  # type: ignore
        import numpy as np
        return cv2, np
    except ImportError:
        return None, None


def _ocr():
    global _ocr_engine
    if _ocr_engine is None:
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore
            _ocr_engine = RapidOCR()
        except Exception:
            _ocr_engine = False
    return _ocr_engine or None


def extract_images(pe: ParsedEmail) -> list[tuple[str, bytes]]:
    imgs = []
    for part in pe.msg.walk():
        if part.get_content_maintype() == "image":
            data = part.get_payload(decode=True) or b""
            imgs.append((part.get_filename() or part.get("Content-ID", "inline") or "inline", data))
    for i, m in enumerate(re.finditer(r"(?i)src\s*=\s*[\"']data:image/[a-z+]+;base64,([a-z0-9+/=\s]+)", pe.html or "")):
        try:
            imgs.append((f"data-uri-{i + 1}", base64.b64decode(re.sub(r"\s", "", m.group(1)))))
        except (binascii.Error, ValueError):
            continue
    return [(n, d) for n, d in imgs if _MIN_BYTES <= len(d) <= _MAX_BYTES][:_MAX_IMAGES]


def _decode_qr(cv2, np, data: bytes) -> list[str]:
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return []
    det = cv2.QRCodeDetector()
    try:
        ok, texts, _, _ = det.detectAndDecodeMulti(img)
        found = [t for t in texts if t] if ok else []
    except cv2.error:
        found = []
    if not found:
        t, _, _ = det.detectAndDecode(img)
        found = [t] if t else []
    return found


def analyze_images(pe: ParsedEmail, cfg: dict) -> dict:
    images = extract_images(pe)
    findings: list[Finding] = []
    qr_texts, ocr_parts, status = [], [], {}

    cv2, np = _cv2()
    status["qr"] = "ok" if cv2 else "未安裝 opencv-python-headless，未解析 QR Code"
    ocr = _ocr() if cfg["image"]["ocr"] else None
    status["ocr"] = ("ok" if ocr else "已停用（IMAGE_OCR=false）" if not cfg["image"]["ocr"]
                     else "未安裝 rapidocr_onnxruntime，未做 OCR")

    for name, data in images:
        if cv2:
            for t in _decode_qr(cv2, np, data):
                qr_texts.append(t)
        if ocr:
            try:
                result, _ = ocr(data)
                text = " ".join(r[1] for r in (result or []) if r and len(r) > 1)
                if text.strip():
                    ocr_parts.append(f"[{name}] {text}")
            except Exception:
                pass

    qr_urls = [t for t in qr_texts if re.match(r"(?i)^(https?://|www\.)", t.strip())]
    if qr_texts and not qr_urls:
        findings.append(Finding(M, "QR_NON_URL", 0.5, f"圖片含 QR Code（內容：{qr_texts[0][:60]}）"))

    # 圖片型信件：可見文字很少，主要內容在圖片裡（常用來躲避文字分析）
    visible = (html_to_text(pe.html)[0] if pe.html else "") or normalize(pe.text)
    remote_imgs = len(re.findall(r"(?i)<img\b[^>]*\bsrc\s*=\s*[\"']?https?://", pe.html or ""))
    if len(re.sub(r"\s", "", visible)) < 60 and (images or remote_imgs):
        findings.append(Finding(M, "IMAGE_ONLY_EMAIL", 1.0,
                                f"信件幾乎沒有文字、內容以圖片呈現（內嵌 {len(images)} 張、外部 {remote_imgs} 張）"))
    if remote_imgs and not images and len(re.sub(r"\s", "", visible)) < 60:
        findings.append(Finding(M, "REMOTE_IMAGES_ONLY", 0.5, "圖片皆為外部連結，基於不連外原則未下載分析"))

    return {"count": len(images), "status": status, "qr_texts": qr_texts, "qr_urls": qr_urls,
            "ocr_text": normalize("\n".join(ocr_parts))[:4000],
            "score": round(sum(f.points for f in findings), 2), "findings": findings}
