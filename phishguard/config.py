"""設定載入：所有參數都來自 .env（系統環境變數可覆寫 .env），程式內不寫死。

校準產生的參數（LLM Platt a/b、決策門檻）由 `calibrate` 寫入 CALIBRATION_FILE，
載入時會覆寫 .env 中對應的初始值。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (環境變數, 型別) —— 全部必填；清單型可留空字串
_SCHEMA = {
    "OLLAMA_HOST": str, "OLLAMA_MODEL": str, "OLLAMA_DEVICE": str, "OLLAMA_TIMEOUT": int,
    "OLLAMA_NUM_CTX": int,
    "LLM_CHUNK_CHARS": int, "LLM_CHUNK_OVERLAP": int, "LLM_MAX_CHUNKS": int,
    "INJECTION_DIFF_THRESHOLD": float,
    "MX_HOSTNAMES": list, "TRUSTED_AUTHSERV_IDS": list, "ARC_TRUSTED_SEALERS": list,
    "PROTECTED_DOMAINS": list, "BRAND_KEYWORDS": list, "FREEMAIL_DOMAINS": list,
    "IP_WHITELIST_FILE": str, "URL_BLOCKLIST_FILE": str, "URL_SHORTENERS": list, "SUSPICIOUS_TLDS": list,
    "IMAGE_OCR": bool,
    "MALWARE_HASH_DB": str,
    "DECISION_THRESHOLD": float, "TARGET_RECALL": float,
    "FUSION_BIAS": float, "FUSION_W_LLM": float, "FUSION_W_HEADER": float,
    "FUSION_W_ATTACHMENT": float, "FUSION_W_URL": float, "FUSION_W_IMAGE": float,
    "FUSION_W_INJECTION": float,
    "INJECTION_MIN_PROB": float, "KNOWN_MALWARE_MIN_PROB": float, "IP_URL_MIN_PROB": float,
    "LLM_PLATT_A": float, "LLM_PLATT_B": float, "CALIBRATION_FILE": str,
    "DATASET_DIR": str, "DATASET_FILES": list, "DATASET_SAMPLE_SIZE": int,
    "DATASET_CAL_RATIO": float, "DATASET_SEED": int, "DATASET_TRAIN_RATIO": float,
    # 微調訓練
    "TRAIN_BASE_MODEL": str, "TRAIN_OUTPUT_DIR": str, "TRAIN_SAMPLE_SIZE": int, "TRAIN_EPOCHS": float,
    "TRAIN_LEARNING_RATE": float, "TRAIN_BATCH_SIZE": int, "TRAIN_GRAD_ACCUM": int,
    "TRAIN_MAX_SEQ_LEN": int, "TRAIN_LORA_R": int, "TRAIN_LORA_ALPHA": int, "TRAIN_LORA_DROPOUT": float,
    "TRAIN_LOAD_IN_4BIT": bool, "TRAIN_INJECTION_AUG": float, "TRAIN_VAL_RATIO": float,
    "TRAIN_OLLAMA_NAME": str, "TRAIN_OLLAMA_QUANTIZE": str, "LLAMA_CPP_DIR": str,
}


def _read_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        elif " #" in v:  # 行尾註解
            v = v.split(" #", 1)[0].rstrip()
        out[k.strip()] = v
    return out


def _cast(name: str, raw: str, typ):
    if typ is list:
        return [s.strip() for s in raw.split(",") if s.strip()]
    if typ is bool:
        if raw.strip().lower() in ("1", "true", "yes", "on"):
            return True
        if raw.strip().lower() in ("0", "false", "no", "off", ""):
            return False
        raise SystemExit(f".env 參數 {name}={raw!r} 必須是 true / false")
    try:
        return typ(raw)
    except ValueError as e:
        raise SystemExit(f".env 參數 {name}={raw!r} 無法轉成 {typ.__name__}") from e


def _brands(items: list[str], protected: list[str]) -> dict[str, list[str]]:
    """BRAND_KEYWORDS：「關鍵字:網域1|網域2」，未指定網域時以 PROTECTED_DOMAINS 為準。"""
    out = {}
    for it in items:
        kw, _, doms = it.partition(":")
        out[kw.strip()] = [d.strip() for d in doms.split("|") if d.strip()] or list(protected)
    return out


def load_config(env_path: str | Path | None = None) -> dict:
    env_path = Path(env_path) if env_path else ROOT / ".env"
    values = _read_env_file(env_path)
    values.update({k: os.environ[k] for k in _SCHEMA if k in os.environ})
    missing = [k for k in _SCHEMA if k not in values]
    if missing:
        raise SystemExit(f"{env_path} 缺少設定：{', '.join(missing)}（可參考 .env.example）")
    e = {k: _cast(k, values[k], t) for k, t in _SCHEMA.items()}
    if e["DATASET_TRAIN_RATIO"] + e["DATASET_CAL_RATIO"] >= 1.0:
        raise SystemExit("DATASET_TRAIN_RATIO + DATASET_CAL_RATIO 必須小於 1（其餘為測試集）")

    def path_of(p: str) -> str:
        return str(Path(p) if Path(p).is_absolute() else ROOT / p)

    cfg = {
        "ollama": {"host": e["OLLAMA_HOST"].rstrip("/"), "model": e["OLLAMA_MODEL"],
                   "device": e["OLLAMA_DEVICE"],
                   "timeout": e["OLLAMA_TIMEOUT"], "num_ctx": e["OLLAMA_NUM_CTX"],
                   "chunk_chars": e["LLM_CHUNK_CHARS"], "chunk_overlap": e["LLM_CHUNK_OVERLAP"],
                   "max_chunks": max(1, e["LLM_MAX_CHUNKS"]), "diff_threshold": e["INJECTION_DIFF_THRESHOLD"]},
        "header": {"mx_hostnames": e["MX_HOSTNAMES"],
                   "trusted_authserv_ids": e["TRUSTED_AUTHSERV_IDS"],
                   "arc_trusted_sealers": e["ARC_TRUSTED_SEALERS"],
                   "protected_domains": e["PROTECTED_DOMAINS"],
                   "brands": _brands(e["BRAND_KEYWORDS"], e["PROTECTED_DOMAINS"]),
                   "freemail_domains": e["FREEMAIL_DOMAINS"]},
        "url": {"ip_whitelist_file": path_of(e["IP_WHITELIST_FILE"]),
                "blocklist_file": path_of(e["URL_BLOCKLIST_FILE"]),
                "shorteners": e["URL_SHORTENERS"], "suspicious_tlds": e["SUSPICIOUS_TLDS"]},
        "image": {"ocr": e["IMAGE_OCR"]},
        "attachment": {"local_hash_db": path_of(e["MALWARE_HASH_DB"])},
        "fusion": {"bias": e["FUSION_BIAS"], "w_llm_logit": e["FUSION_W_LLM"],
                   "w_header": e["FUSION_W_HEADER"], "w_attachment": e["FUSION_W_ATTACHMENT"],
                   "w_url": e["FUSION_W_URL"], "w_image": e["FUSION_W_IMAGE"],
                   "w_injection": e["FUSION_W_INJECTION"]},
        "overrides": {"injection_min_prob": e["INJECTION_MIN_PROB"],
                      "known_malware_min_prob": e["KNOWN_MALWARE_MIN_PROB"],
                      "ip_url_min_prob": e["IP_URL_MIN_PROB"]},
        "llm_platt": {"a": e["LLM_PLATT_A"], "b": e["LLM_PLATT_B"]},
        "threshold": e["DECISION_THRESHOLD"],
        "target_recall": e["TARGET_RECALL"],
        "calibration_file": path_of(e["CALIBRATION_FILE"]),
        "dataset": {"dir": path_of(e["DATASET_DIR"]), "files": e["DATASET_FILES"],
                    "sample_size": e["DATASET_SAMPLE_SIZE"], "cal_ratio": e["DATASET_CAL_RATIO"],
                    "train_ratio": e["DATASET_TRAIN_RATIO"], "seed": e["DATASET_SEED"]},
        "train": {"base_model": e["TRAIN_BASE_MODEL"], "output_dir": path_of(e["TRAIN_OUTPUT_DIR"]),
                  "sample_size": e["TRAIN_SAMPLE_SIZE"], "epochs": e["TRAIN_EPOCHS"],
                  "lr": e["TRAIN_LEARNING_RATE"], "batch_size": e["TRAIN_BATCH_SIZE"],
                  "grad_accum": e["TRAIN_GRAD_ACCUM"], "max_seq_len": e["TRAIN_MAX_SEQ_LEN"],
                  "lora_r": e["TRAIN_LORA_R"], "lora_alpha": e["TRAIN_LORA_ALPHA"],
                  "lora_dropout": e["TRAIN_LORA_DROPOUT"], "load_in_4bit": e["TRAIN_LOAD_IN_4BIT"],
                  "injection_aug": e["TRAIN_INJECTION_AUG"], "val_ratio": e["TRAIN_VAL_RATIO"],
                  "ollama_name": e["TRAIN_OLLAMA_NAME"], "ollama_quantize": e["TRAIN_OLLAMA_QUANTIZE"],
                  "llama_cpp_dir": e["LLAMA_CPP_DIR"]},
        "calibrated": False,
    }
    from .hardware import detect  # 偵測 GPU/CPU，決定傳給 Ollama 的 num_gpu
    cfg["hardware"] = detect(e["OLLAMA_DEVICE"])

    cal = Path(cfg["calibration_file"])
    if cal.exists():
        data = json.loads(cal.read_text(encoding="utf-8"))
        from .llm_check import LLM_VERSION
        if data.get("model") == cfg["ollama"]["model"] and data.get("llm_version") == LLM_VERSION:
            cfg["llm_platt"] = data.get("llm_platt", cfg["llm_platt"])
            cfg["threshold"] = data.get("threshold", cfg["threshold"])
            cfg["calibrated"] = True
        else:
            import sys
            print(f"⚠ {cal.name} 的模型/判讀方法（{data.get('model')}, {data.get('llm_version', 'v1')}）"
                  f"與目前（{cfg['ollama']['model']}, {LLM_VERSION}）不同，已忽略；請重新執行 calibrate",
                  file=sys.stderr)
    return cfg
