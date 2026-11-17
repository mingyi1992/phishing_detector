"""(4) 評分指標與校準。

資料來源（擇一）：
  * Kaggle「Phish No More」資料集目錄（.env 的 DATASET_DIR / DATASET_FILES）
      欄位：sender, receiver, date, subject, body, label[, urls]；Enron / Ling 只有 subject, body, label
      注意：CEAS / Enron / Ling / SpamAssassin 的 label=1 包含一般垃圾信（spam），不只釣魚信。
  * .eml 目錄：<dir>/phishing/*.eml（1）與 <dir>/legit/*.eml（0）

切分：以內容雜湊固定切成校準集（cal）與測試集（test），比例為 DATASET_CAL_RATIO，兩者永不重疊。
抽樣：每次依（來源檔 × 標記）分層抽 DATASET_SAMPLE_SIZE 封。
CSV 重建的信件沒有驗證標頭、Received 與附件，所以這些檢查在資料集評估中不會扣分；
資料集主要用於校準與評估 LLM 及整體門檻。

calibrate：在 cal 上擬合 LLM Platt scaling（a, b），並找出達到 TARGET_RECALL 的最高門檻。
evaluate ：在 test 上輸出混淆矩陣、Accuracy / Precision / Recall / F1 / F2 / FPR / FNR /
           ROC-AUC / PR-AUC / MCC / Brier / Log-loss / ECE、各來源的召回率與漏抓清單。
LLM 結果快取在 cache/，中斷後重跑會接續。
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

from .analyzer import analyze_parsed, fuse
from .common import sigmoid
from .config import ROOT
from .parser import load_eml, parse_bytes

csv.field_size_limit(2**31 - 1)

_LEGIT_DIRS = ("legit", "ham", "benign")
_MAL_DIRS = ("phishing", "malicious", "spam")


# ---------------------------------------------------------------- 資料載入

def _clean_header(v: str) -> str:
    return " ".join(str(v or "").split())[:500]


def _record_to_raw(rec: dict) -> bytes:
    hdr = []
    for name, key in (("From", "sender"), ("To", "receiver"), ("Date", "date"), ("Subject", "subject")):
        if rec.get(key):
            hdr.append(f"{name}: {_clean_header(rec[key])}")
    hdr += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: 8bit"]
    return ("\n".join(hdr) + "\n\n" + str(rec.get("body") or "")).encode("utf-8", errors="replace")


def _load_csv_records(files: list[Path]) -> list[dict]:
    seen, out = set(), []
    for f in files:
        with f.open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                row = {k.strip().lower(): v for k, v in row.items() if k}
                if "body" not in row and "text_combined" in row:
                    row["body"] = row["text_combined"]
                try:
                    label = int(float(row.get("label", "")))
                except ValueError:
                    continue
                key = hashlib.sha256(f"{row.get('subject','')}\0{row.get('body','')}".encode(
                    "utf-8", errors="replace")).hexdigest()
                if key in seen:  # 跨檔去重
                    continue
                seen.add(key)
                out.append({"id": key, "source": f.name, "label": label,
                            "sender": row.get("sender"), "receiver": row.get("receiver"),
                            "date": row.get("date"), "subject": row.get("subject"), "body": row.get("body")})
    return out


def _load_eml_records(d: Path) -> list[dict]:
    out = []
    for names, lab in ((_MAL_DIRS, 1), (_LEGIT_DIRS, 0)):
        for sub in names:
            for p in sorted((d / sub).rglob("*.eml")) if (d / sub).is_dir() else []:
                out.append({"id": hashlib.sha256(p.read_bytes()).hexdigest(), "source": sub,
                            "label": lab, "path": str(p)})
    return out


def load_records(cfg: dict, dataset: str | None = None) -> tuple[list[dict], str]:
    ds = Path(dataset or cfg["dataset"]["dir"])
    if ds.is_file():
        return _load_csv_records([ds]), "csv"
    if any((ds / s).is_dir() for s in _LEGIT_DIRS + _MAL_DIRS):
        return _load_eml_records(ds), "eml"
    files = [ds / f for f in cfg["dataset"]["files"]]
    missing = [str(f) for f in files if not f.exists()]
    if missing:
        raise SystemExit(f"找不到資料檔：{', '.join(missing)}")
    return _load_csv_records(files), "csv"


def part_of(rec_id: str, cfg: dict) -> str:
    """以內容雜湊固定切分：[0, train) → train，[train, train+cal) → cal，其餘 → test。"""
    u = int(rec_id[:8], 16) / 0xFFFFFFFF
    tr, cal = cfg["dataset"]["train_ratio"], cfg["dataset"]["cal_ratio"]
    return "train" if u < tr else "cal" if u < tr + cal else "test"


def select(records: list[dict], cfg: dict, part: str, sample: int | None) -> list[dict]:
    if part != "all":
        records = [r for r in records if part_of(r["id"], cfg) == part]
    n = cfg["dataset"]["sample_size"] if sample is None else sample
    if n and n < len(records):
        rng = random.Random(cfg["dataset"]["seed"])
        groups = defaultdict(list)
        for r in records:
            groups[(r["source"], r["label"])].append(r)
        chosen = []
        for key in sorted(groups):
            g = groups[key]
            k = max(1, round(n * len(g) / len(records)))
            chosen += rng.sample(g, min(k, len(g)))
        records = chosen
    return records


# ---------------------------------------------------------------- 特徵（含快取）

def collect_features(records: list[dict], kind: str, cfg: dict, use_llm: bool = True) -> list[dict]:
    model = cfg["ollama"]["model"]
    cache_dir = ROOT / "cache"
    cache_dir.mkdir(exist_ok=True)
    from .llm_check import LLM_VERSION
    cache_file = cache_dir / (f"features_{model.replace(':', '_').replace('/', '_')}_{LLM_VERSION}_"
                              f"c{cfg['ollama']['chunk_chars']}x{cfg['ollama']['max_chunks']}_"
                              f"{'llm' if use_llm else 'nollm'}.jsonl")
    cache = {}
    if cache_file.exists():
        for line in cache_file.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            cache[d["id"]] = d["features"]

    rows, t0, done_new = [], time.time(), 0
    todo = sum(1 for r in records if r["id"] not in cache)
    print(f"共 {len(records)} 封，其中 {len(records) - todo} 封已有快取，需推論 {todo} 封")
    # 快取只存 LLM 結果；規則類特徵（標頭、附件、注入）每次重算，改規則不必重跑 LLM
    llm_keys = ("llm_raw_logit", "llm_available")
    with cache_file.open("a", encoding="utf-8") as out:
        for r in records:
            pe = load_eml(r["path"]) if kind == "eml" else parse_bytes(_record_to_raw(r))
            cached = cache.get(r["id"])
            if cached is not None:
                rep = analyze_parsed(pe, cfg, use_llm=False, synthetic=(kind == "csv"))
                feat = {**rep["features"], **{k: cached[k] for k in llm_keys}}
            else:
                rep = analyze_parsed(pe, cfg, use_llm=use_llm, explain=False, synthetic=(kind == "csv"))
                if use_llm and rep["content"]["error"]:
                    # 上線時這種信會被隔離（模型未成功啟用）；評估時排除，避免污染指標
                    print(f"  ! 模型未成功啟用，略過（{r['source']} {r['id'][:10]}）：{rep['content']['error']}")
                    continue
                feat = rep["features"]
                out.write(json.dumps({"id": r["id"], "features": {k: feat[k] for k in llm_keys}},
                                     ensure_ascii=False) + "\n")
                out.flush()
                done_new += 1
                if done_new == 1 and use_llm:  # 第一封推論後回報模型實際在 GPU 還是 CPU
                    from .hardware import describe_placement, placement
                    for line in describe_placement(placement(cfg["ollama"]["host"], model), cfg["hardware"]):
                        print(f"  [運算資源] {line}", flush=True)
                if done_new % 20 == 0 or done_new == todo:
                    el = time.time() - t0
                    eta = el / done_new * (todo - done_new)
                    print(f"  {done_new}/{todo}  已用 {el/60:.1f} 分，預估剩餘 {eta/60:.1f} 分", flush=True)
            rows.append({"id": r["id"], "source": r["source"], "label": r["label"],
                         "subject": (r.get("subject") or r.get("path") or "")[:80], **feat})
    return rows


def _fused_probs(rows: list[dict], cfg: dict) -> np.ndarray:
    a, b = cfg["llm_platt"]["a"], cfg["llm_platt"]["b"]
    out = []
    for r in rows:
        f = dict(r)
        f["llm_cal_logit"] = a * r["llm_raw_logit"] + b if r["llm_available"] else 0.0
        out.append(fuse(f, cfg)[0])
    return np.array(out)


# ---------------------------------------------------------------- 指標

def ece_score(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if m.any():
            ece += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(ece)


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    pred = (p >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    div = lambda a, b: a / b if b else 0.0  # noqa: E731
    prec, rec = div(tp, tp + fp), div(tp, tp + fn)
    res = {
        "confusion_matrix": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
        "accuracy": div(tp + tn, len(y)), "precision": prec, "recall": rec,
        "f1": div(2 * prec * rec, prec + rec),
        "f2": div(5 * prec * rec, 4 * prec + rec),  # 召回率權重較高
        "specificity": div(tn, tn + fp), "fpr": div(fp, fp + tn), "fnr": div(fn, fn + tp),
        "brier": float(np.mean((p - y) ** 2)),
        "log_loss": float(-np.mean(y * np.log(np.clip(p, 1e-7, 1)) + (1 - y) * np.log(np.clip(1 - p, 1e-7, 1)))),
        "ece": ece_score(y, p),
    }
    if len(set(y.tolist())) == 2:
        from sklearn.metrics import average_precision_score, matthews_corrcoef, roc_auc_score
        res["roc_auc"] = float(roc_auc_score(y, p))
        res["pr_auc"] = float(average_precision_score(y, p))
        res["mcc"] = float(matthews_corrcoef(y, pred))
    return res


def _print_metrics(name: str, m: dict) -> None:
    cm = m["confusion_matrix"]
    print(f"\n=== {name} ===")
    print("                 預測正常   預測惡意")
    print(f"  實際正常 (0)   TN={cm['TN']:<7} FP={cm['FP']}")
    print(f"  實際惡意 (1)   FN={cm['FN']:<7} TP={cm['TP']}")
    keys = ["recall", "precision", "f2", "f1", "accuracy", "specificity", "fpr", "fnr",
            "roc_auc", "pr_auc", "mcc", "brier", "log_loss", "ece"]
    print("  " + "  ".join(f"{k}={m[k]:.4f}" for k in keys if k in m))


def threshold_for_recall(y: np.ndarray, p: np.ndarray, target: float) -> float:
    """回傳仍能達到目標召回率的最高門檻（門檻越高，誤擋越少）。"""
    pos = np.sort(p[y == 1])
    if len(pos) == 0:
        return 0.5
    k = int(np.floor((1 - target) * len(pos)))  # 最多允許漏掉 k 封
    return float(max(pos[k] - 1e-9, 1e-6))


# ---------------------------------------------------------------- 校準

def calibrate(cfg: dict, dataset: str | None = None, sample: int | None = None) -> dict:
    from sklearn.linear_model import LogisticRegression

    records, kind = load_records(cfg, dataset)
    recs = select(records, cfg, "cal", sample)
    rows = collect_features(recs, kind, cfg)
    y = np.array([r["label"] for r in rows])
    if len(set(y.tolist())) < 2:
        raise SystemExit("校準資料必須同時包含惡意與正常信件")

    llm_rows = [r for r in rows if r["llm_available"]]
    x = np.array([[r["llm_raw_logit"]] for r in llm_rows])
    yl = np.array([r["label"] for r in llm_rows])
    lr = LogisticRegression(C=100.0).fit(x, yl)  # Platt scaling
    cfg["llm_platt"] = {"a": float(lr.coef_[0][0]), "b": float(lr.intercept_[0])}

    p = _fused_probs(rows, cfg)
    thr = threshold_for_recall(y, p, cfg["target_recall"])
    cfg["threshold"] = thr
    m = metrics(y, p, thr)
    _print_metrics(f"校準集（門檻 {thr:.4f}，目標召回率 {cfg['target_recall']}）", m)

    from .llm_check import LLM_VERSION
    out = {"model": cfg["ollama"]["model"], "llm_version": LLM_VERSION, "n_samples": len(rows), "part": "cal",
           "llm_platt": cfg["llm_platt"], "threshold": thr, "target_recall": cfg["target_recall"],
           "cal_metrics": m}
    Path(cfg["calibration_file"]).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nLLM Platt：a={cfg['llm_platt']['a']:.4f}  b={cfg['llm_platt']['b']:.4f}")
    print(f"已寫入 {cfg['calibration_file']}；請接著執行 evaluate（測試集）確認泛化表現。")
    return out


# ---------------------------------------------------------------- 評估

def evaluate(cfg: dict, dataset: str | None = None, part: str = "test", sample: int | None = None,
             threshold: float | None = None, out_dir: str | Path | None = None, use_llm: bool = True) -> dict:
    if not cfg["calibrated"]:
        print("⚠ 尚未校準（找不到對應模型的 calibration.json），使用 .env 的初始參數")
    thr = cfg["threshold"] if threshold is None else threshold
    records, kind = load_records(cfg, dataset)
    recs = select(records, cfg, part if kind == "csv" else "all", sample)
    rows = collect_features(recs, kind, cfg, use_llm=use_llm)
    y = np.array([r["label"] for r in rows])

    fused = _fused_probs(rows, cfg)
    variants = {"融合（最終判定）": fused}
    if use_llm:
        a, b = cfg["llm_platt"]["a"], cfg["llm_platt"]["b"]
        variants["只用 LLM（logit 校準）"] = np.array([sigmoid(a * r["llm_raw_logit"] + b) for r in rows])
    if kind == "eml":
        w = cfg["fusion"]
        variants["只用標頭規則"] = np.array([sigmoid(w["bias"] + w["w_header"] * r["header"]) for r in rows])

    report = {"n": len(rows), "positives": int(y.sum()), "part": part, "threshold": thr,
              "calibrated": cfg["calibrated"], "results": {}, "per_source": {}}
    for name, p in variants.items():
        m = metrics(y, p, thr)
        report["results"][name] = m
        _print_metrics(f"{name}  門檻={thr:.4f}", m)

    print("\n各來源（融合判定）：")
    for src in sorted({r["source"] for r in rows}):
        idx = np.array([r["source"] == src for r in rows])
        ys, ps = y[idx], fused[idx]
        pos, neg = ys == 1, ys == 0
        d = {"n": int(idx.sum()),
             "recall": float((ps[pos] >= thr).mean()) if pos.any() else None,
             "fpr": float((ps[neg] >= thr).mean()) if neg.any() else None}
        report["per_source"][src] = d
        fmt = lambda v: "-" if v is None else f"{v:.3f}"  # noqa: E731
        print(f"  {src:<20} n={d['n']:<5} recall={fmt(d['recall'])}  FPR={fmt(d['fpr'])}")

    errs = [{"type": "FN" if r["label"] else "FP", "source": r["source"], "subject": r["subject"],
             "prob": round(float(pp), 4), "llm_raw_logit": r["llm_raw_logit"]}
            for r, pp in zip(rows, fused) if (pp >= thr) != bool(r["label"])]
    report["errors"] = errs
    fns = [e for e in errs if e["type"] == "FN"]
    if fns:
        print(f"\n漏抓（FN）{len(fns)} 封，前 15 封：")
        for e in sorted(fns, key=lambda e: e["prob"])[:15]:
            print(f"  p={e['prob']:.3f}  [{e['source']}] {e['subject']}")

    if out_dir:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "metrics.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        _plots(y, fused, thr, out_dir)
        print(f"\n報告已輸出到 {out_dir}（metrics.json、evaluation.png）")
    sys.stdout.flush()
    return report


def _plots(y: np.ndarray, p: np.ndarray, thr: float, out_dir: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.calibration import calibration_curve
        from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay
    except ImportError:
        return
    two = len(set(y.tolist())) == 2
    pred = (p >= thr).astype(int)
    fig, ax = plt.subplots(1, 4 if two else 1, figsize=(20, 4.5), squeeze=False)
    ConfusionMatrixDisplay.from_predictions(y, pred, display_labels=["legit", "malicious"],
                                            cmap="Blues", ax=ax[0][0], colorbar=False)
    ax[0][0].set_title(f"Confusion matrix (thr={thr:.3f})")
    if two:
        RocCurveDisplay.from_predictions(y, p, ax=ax[0][1])
        ax[0][1].set_title("ROC")
        PrecisionRecallDisplay.from_predictions(y, p, ax=ax[0][2])
        ax[0][2].set_title("Precision-Recall")
        frac, mean = calibration_curve(y, p, n_bins=min(10, max(2, len(y) // 20)))
        ax[0][3].plot([0, 1], [0, 1], "--", color="gray")
        ax[0][3].plot(mean, frac, "o-")
        ax[0][3].set_xlabel("predicted probability")
        ax[0][3].set_ylabel("observed frequency")
        ax[0][3].set_title("Reliability diagram")
    fig.tight_layout()
    fig.savefig(out_dir / "evaluation.png", dpi=120)
    plt.close(fig)
