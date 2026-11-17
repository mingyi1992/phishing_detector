"""整合各模組並做分數融合。

順序：圖片（QR/OCR）→ 網址（含 QR 網址）→ LLM（含 OCR 文字）→ 標頭 → 附件 → 融合。

融合模型為 logistic regression（權重來自 .env）：
    final_logit = BIAS + W_LLM·LLM校準logit + W_HEADER·標頭 + W_ATTACHMENT·附件 + W_URL·網址
                  + W_IMAGE·圖片 + W_INJECTION·注入
硬性規則（.env）：
  * LLM 未成功執行 → 直接隔離，原因「模型未成功啟用」（fail-closed）
  * 附件雜湊命中已知惡意檔 → 機率下限 KNOWN_MALWARE_MIN_PROB
  * 網址直接使用非白名單 IP → 機率下限 IP_URL_MIN_PROB
  * 偵測到提示詞注入 → 機率下限 INJECTION_MIN_PROB
"""
from __future__ import annotations

from pathlib import Path

from .attachment_check import analyze_attachments
from .common import logit, sigmoid
from .header_check import analyze_headers
from .image_check import analyze_images
from .llm_check import analyze_content
from .parser import ParsedEmail, load_eml
from .url_check import analyze_urls

QUARANTINE_REASON = "模型未成功啟用"


def features_of(report: dict, cfg: dict) -> dict:
    llm = report["content"]
    if llm["available"]:
        a, b = cfg["llm_platt"]["a"], cfg["llm_platt"]["b"]
        llm_cal_logit = a * llm["raw_logit"] + b
    else:
        llm_cal_logit = 0.0
    return {
        "llm_raw_logit": llm["raw_logit"] if llm["available"] else 0.0,
        "llm_cal_logit": llm_cal_logit,
        "llm_available": llm["available"],
        "llm_failed": bool(llm.get("error")),
        "header": report["header"]["score"],
        "attachment": report["attachments"]["score"],
        "url": report["urls"]["score"],
        "image": report["images"]["score"],
        "injection": llm["injection_score"],
        "known_malicious": report["attachments"]["known_malicious"],
        "ip_url": bool(report["urls"]["ip_url_hits"]),
    }


def contributions(feat: dict, cfg: dict) -> dict:
    w = cfg["fusion"]
    return {"LLM 內容判讀": w["w_llm_logit"] * feat["llm_cal_logit"],
            "標頭檢查": w["w_header"] * feat["header"],
            "附件檢查": w["w_attachment"] * feat["attachment"],
            "網址分析": w["w_url"] * feat.get("url", 0.0),
            "圖片分析": w["w_image"] * feat.get("image", 0.0),
            "提示詞注入": w["w_injection"] * feat["injection"]}


def fuse(feat: dict, cfg: dict) -> tuple[float, list[str]]:
    z = cfg["fusion"]["bias"] + sum(contributions(feat, cfg).values())
    p = sigmoid(z)
    ov = cfg["overrides"]
    overrides = []
    for cond, floor, msg in (
        (feat["known_malicious"], ov["known_malware_min_prob"], "附件為已知惡意檔"),
        (feat.get("ip_url"), ov["ip_url_min_prob"], "連結直接使用非白名單 IP 位址"),
        (feat["injection"] >= 1.0, ov["injection_min_prob"], "偵測到提示詞注入"),
    ):
        if cond and p < floor:
            p = floor
            overrides.append(f"{msg} → 機率下限 {floor}")
    return p, overrides


def label_of(p: float, threshold: float) -> str:
    if p >= max(threshold, 0.8):
        return "惡意/詐騙（攔截）"
    if p >= threshold:
        return "可疑（攔截，建議人工複核）"
    if p >= threshold * 0.5:
        return "低風險（放行，仍請留意）"
    return "正常"


def _reason_summary(report: dict, feat: dict, cfg: dict, overrides: list[str]) -> list[str]:
    lines = list(overrides)
    contrib = sorted(contributions(feat, cfg).items(), key=lambda kv: -abs(kv[1]))
    lines.append("各模組對 logit 的貢獻：" + "、".join(f"{k} {v:+.2f}" for k, v in contrib if abs(v) > 0.01))
    findings = [f for key in ("header", "attachments", "urls", "images") for f in report[key]["findings"]
                if f.points > 0]
    for f in sorted(findings, key=lambda f: -f.points)[:8]:
        lines.append(f"[{f.module}] {f.message}")
    for f in report["content"]["findings"][:4]:
        lines.append(f"[{f.module}] {f.message}")
    for r in report["content"]["reasons"][:4]:
        lines.append(f"[LLM] {r}")
    return lines


def analyze_parsed(pe: ParsedEmail, cfg: dict, use_llm: bool = True, explain: bool = True,
                   synthetic: bool = False) -> dict:
    images = analyze_images(pe, cfg)
    report = {
        "subject": pe.subject,
        "from": str(pe.msg.get("From", "")),
        "images": images,
        "urls": analyze_urls(pe, cfg, extra=[(u, "", "qr") for u in images["qr_urls"]]),
        "content": analyze_content(pe, cfg, use_llm=use_llm, explain=explain, ocr_text=images["ocr_text"]),
        "header": analyze_headers(pe, cfg, synthetic=synthetic),
        "attachments": analyze_attachments(pe, cfg),
    }
    feat = features_of(report, cfg)
    p, overrides = fuse(feat, cfg)
    thr = cfg["threshold"]
    final = {"probability": round(p, 4), "logit": round(logit(p), 3), "threshold": thr,
             "calibrated": cfg["calibrated"], "label": label_of(p, thr), "is_malicious": p >= thr,
             "quarantined": False, "overrides": overrides}
    if use_llm and feat["llm_failed"]:   # fail-closed
        final.update(label=f"隔離（{QUARANTINE_REASON}）", is_malicious=True, quarantined=True,
                     quarantine_reason=QUARANTINE_REASON)
        overrides.insert(0, f"{QUARANTINE_REASON}（{report['content']['error'][:120]}）→ 直接隔離，"
                            f"上方機率僅為規則分數，請待模型恢復後重新分析")
    elif not use_llm:
        overrides.insert(0, "未使用 LLM（--no-llm），僅規則判斷")
    final["reasons"] = _reason_summary(report, feat, cfg, overrides)
    report["features"] = feat
    report["final"] = final
    return report


def analyze_file(path: str | Path, cfg: dict, use_llm: bool = True) -> dict:
    rep = analyze_parsed(load_eml(path), cfg, use_llm=use_llm)
    rep["file"] = str(path)
    return rep
