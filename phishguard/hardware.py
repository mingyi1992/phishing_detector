"""運算資源偵測：有 GPU 就用 GPU，沒有才用 CPU。

實際把模型放到 GPU 或 CPU 的是 Ollama；本模組負責：
  1. 偵測本機 GPU（NVIDIA：nvidia-smi；AMD：rocm-smi；Apple Silicon：Metal），只呼叫本機指令。
  2. 依 .env 的 OLLAMA_DEVICE 產生 Ollama 的 num_gpu 參數：
       auto：偵測到 GPU → 交給 Ollama 自動決定可放進 VRAM 的層數；沒有 GPU → num_gpu=0（純 CPU）
       gpu ：強制所有層放 GPU（num_gpu=999），VRAM 不足可能載入失敗
       cpu ：強制只用 CPU（num_gpu=0）
  3. 模型載入後查詢 Ollama /api/ps，回報實際有多少比例在 GPU 上；有 GPU 卻跑在 CPU 時發出警告。
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

import requests


@dataclass
class GPU:
    vendor: str
    name: str
    vram_mb: int | None = None
    driver: str | None = None


@dataclass
class Hardware:
    gpus: list[GPU] = field(default_factory=list)
    cpu: str = ""
    device: str = "cpu"          # 實際要求 Ollama 使用的裝置：gpu / cpu
    mode: str = "auto"           # .env 設定值
    options: dict = field(default_factory=dict)   # 傳給 Ollama 的 options
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.gpus:
            g = "；".join(f"{x.name}" + (f" {x.vram_mb} MB" if x.vram_mb else "")
                         + (f"（驅動 {x.driver}）" if x.driver else "") for x in self.gpus)
        else:
            g = "未偵測到可用 GPU"
        return f"GPU：{g}\nCPU：{self.cpu}\n設定 OLLAMA_DEVICE={self.mode} → 使用 {self.device.upper()}"


def _run(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _nvidia() -> list[GPU]:
    out = _run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
    gpus = []
    for line in (out or "").strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3:
            try:
                vram = int(float(parts[1]))
            except ValueError:
                vram = None
            gpus.append(GPU("NVIDIA", parts[0], vram, parts[2]))
    return gpus


def _amd() -> list[GPU]:
    out = _run(["rocm-smi", "--showproductname"])
    return [GPU("AMD", line.split(":", 1)[-1].strip()) for line in (out or "").splitlines()
            if "Card series" in line]


def _apple() -> list[GPU]:
    if sys.platform == "darwin" and platform.machine() == "arm64":
        return [GPU("Apple", "Apple Silicon (Metal)")]
    return []


def _cpu_name() -> str:
    if sys.platform == "win32":
        out = _run(["powershell", "-NoProfile", "-Command",
                    "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name"])
        if out and out.strip():
            return out.strip()
    return platform.processor() or platform.machine()


def detect(mode: str = "auto") -> Hardware:
    mode = (mode or "auto").lower()
    if mode not in ("auto", "gpu", "cpu"):
        raise SystemExit(f"OLLAMA_DEVICE 只能是 auto / gpu / cpu（目前為 {mode!r}）")
    hw = Hardware(gpus=_nvidia() or _amd() or _apple(), cpu=_cpu_name(), mode=mode)
    if mode == "cpu":
        hw.device, hw.options = "cpu", {"num_gpu": 0}
    elif mode == "gpu":
        hw.device, hw.options = "gpu", {"num_gpu": 999}
        if not hw.gpus:
            hw.notes.append("OLLAMA_DEVICE=gpu，但沒有偵測到 GPU；Ollama 可能載入失敗或退回 CPU")
    else:  # auto
        if hw.gpus:
            hw.device, hw.options = "gpu", {}   # 交給 Ollama 依 VRAM 自動分配層數
        else:
            hw.device, hw.options = "cpu", {"num_gpu": 0}
    return hw


def placement(host: str, model: str, timeout: int = 10) -> dict | None:
    """查詢 Ollama 已載入模型實際的 GPU/CPU 分配（需先呼叫過模型）。"""
    try:
        r = requests.get(f"{host}/api/ps", timeout=timeout)
        r.raise_for_status()
    except requests.RequestException:
        return None
    for m in r.json().get("models", []):
        if m.get("name") == model or m.get("model") == model:
            size, vram = m.get("size", 0) or 0, m.get("size_vram", 0) or 0
            pct = round(100 * vram / size) if size else 0
            return {"size_mb": size // 2**20, "vram_mb": vram // 2**20, "gpu_percent": pct,
                    "context": m.get("context_length")}
    return None


def describe_placement(p: dict | None, hw: Hardware) -> list[str]:
    if p is None:
        return ["無法取得模型載入狀態（模型尚未載入或 Ollama 未啟動）"]
    pct = p["gpu_percent"]
    where = "100% GPU" if pct >= 100 else ("100% CPU" if pct == 0 else f"{pct}% GPU / {100 - pct}% CPU")
    lines = [f"模型實際載入：{where}（模型 {p['size_mb']} MB，VRAM 使用 {p['vram_mb']} MB）"]
    if hw.gpus and hw.device == "gpu" and pct == 0:
        lines.append("⚠ 偵測到 GPU 但模型跑在 CPU：請確認已安裝最新 NVIDIA 驅動，並重新啟動 Ollama")
    elif hw.device == "gpu" and 0 < pct < 100:
        lines.append("⚠ VRAM 不足，部分層在 CPU（速度會變慢）：可降低 OLLAMA_NUM_CTX、"
                     "LLM_MAX_BODY_CHARS，或改用較小的模型")
    return lines
