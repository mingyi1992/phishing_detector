"""命令列介面。

  python -m phishguard analyze   信件.eml [...] [--json] [--no-llm]
  python -m phishguard calibrate [資料集] [--sample N]
  python -m phishguard evaluate  [資料集] [--part test|cal|all] [--sample N] [--threshold T] [--out reports/]
所有參數（模型、門檻、權重、資料集路徑…）都在 .env 設定。
"""
from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze_file
from .config import load_config


def _print_report(rep: dict) -> None:
    fin = rep["final"]
    print("=" * 78)
    print(f"檔案：{rep.get('file')}")
    print(f"寄件者：{rep['from']}\n主旨：{rep['subject']}")
    print(f"\n▶ 判定：{fin['label']}    惡意機率 = {fin['probability']:.4f}   (logit {fin['logit']:+.2f})"
          f"   門檻 {fin['threshold']:.3f}{'' if fin['calibrated'] else '（未校準）'}")
    print("  判定原因：")
    for o in fin["reasons"]:
        print(f"   • {o}")

    h = rep["header"]
    print(f"\n[1] 標頭檢查  風險分數 {h['score']}")
    for w in h.get("config_warnings", []):
        print(f"    ⚠ 設定提醒：{w}")
    au = h["auth"]
    print(f"    SPF={au['spf']}  DKIM={au['dkim']}  DMARC={au['dmarc']}  ARC={au['arc']}  "
          f"（採信來源：{au['source'] or '無'}）")
    tb = h["trust_boundary"]
    print(f"    信任邊界：{tb['method'] or '找不到'}  真實來源 IP={tb['origin_ip'] or '-'}  HELO={tb['origin_helo'] or '-'}")
    idt = h["identity"]
    print(f"    From={idt['from']}  Reply-To={idt['reply_to'] or '-'}  Return-Path={idt['return_path'] or '-'}")
    if h["received_path"]:
        print("    Received 路徑（由早到晚；untrusted = 寄件端可偽造）：")
        for hop in h["received_path"]:
            print(f"      [{hop.get('trust'):<9}] {hop.get('from') or '?'} [{hop.get('ip') or '-'}] → "
                  f"{hop.get('by') or '?'}  {hop.get('time') or ''}")
    for f in h["findings"]:
        print(f"    {f.points:+.1f}  {f.message}")

    u = rep["urls"]
    print(f"\n[2] 網址分析  共 {u['count']} 個  風險分數 {u['score']}")
    for it in u["items"][:10]:
        extra = f"  IP={it['ip']}{'（白名單）' if it.get('ip_whitelisted') else ''}" if it.get("ip") else ""
        print(f"    • [{it['source']}] {it['url'][:100]}{extra}")
    for f in u["findings"]:
        print(f"    {f.points:+.1f}  {f.message}")

    im = rep["images"]
    print(f"\n[3] 圖片分析  共 {im['count']} 張  風險分數 {im['score']}")
    if im["count"]:
        print(f"    QR Code：{im['status']['qr']}  OCR：{im['status']['ocr']}")
    if im["qr_texts"]:
        print("    QR Code 內容：" + "；".join(t[:100] for t in im["qr_texts"]))
    if im["ocr_text"]:
        print(f"    OCR 文字：{im['ocr_text'][:200]}")
    for f in im["findings"]:
        print(f"    {f.points:+.1f}  {f.message}")

    c = rep["content"]
    print("\n[4] SLM 內容判讀")
    if c["available"]:
        print(f"    raw logit={c['raw_logit']:+.3f}（{c['chunks']} 段取最高，各段：{c['chunk_logits']}）  "
              f"校準後詐騙機率={c['calibrated_prob']:.4f}  文字判決={c['verdict']}")
        d = c.get("differential")
        if d:
            print(f"    差異測試：可疑句 {d['suspect_sentences']} 句{'＋隱藏文字' if d['hidden_removed'] else ''}，"
                  f"移除前 {d['logit_with']:+.2f} → 移除後 {d['logit_without']:+.2f}（Δ {d['delta']:+.2f}）"
                  f"  {'⚠ 確認操控模型' if d['manipulation'] else '未發現操控'}")
        if c.get("note"):
            print(f"    註：{c['note']}")
        for r in c["reasons"]:
            print(f"    - {r}")
        if c["red_flags"]:
            print("    可疑元素：" + "；".join(c["red_flags"]))
    elif c["error"]:
        print(f"    ✖ 模型未成功啟用：{c['error']}")
    else:
        print("    未執行（--no-llm）")
    print(f"    提示詞注入分數 {c['injection_score']}")
    for f in c["findings"]:
        print(f"    ⚠ {f.message}")

    a = rep["attachments"]
    print(f"\n[5] 附件檢查  共 {a['count']} 個  風險分數 {a['score']}")
    for it in a["items"]:
        print(f"    • {it['filename']}  ({it['size']} bytes, 檔頭={it['magic']})  sha256={it['hashes']['sha256']}")
    for f in a["findings"]:
        print(f"    {f.points:+.1f}  {f.message}")
    print()


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _show_placement(cfg: dict) -> None:
    from .hardware import describe_placement, placement
    p = placement(cfg["ollama"]["host"], cfg["ollama"]["model"])
    for line in describe_placement(p, cfg["hardware"]):
        _err(f"[運算資源] {line}")


def _jsonable(o):
    if hasattr(o, "to_dict"):
        return o.to_dict()
    raise TypeError(type(o))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard", description="惡意 / 詐騙郵件偵測")
    ap.add_argument("--env", help=".env 路徑（預設為專案根目錄的 .env）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="分析一或多封 .eml")
    a.add_argument("files", nargs="+")
    a.add_argument("--json", action="store_true", help="輸出 JSON")
    a.add_argument("--no-llm", action="store_true", help="不呼叫 LLM（只做規則檢查）")

    sub.add_parser("hwinfo", help="偵測 GPU/CPU，並載入模型確認實際使用的運算裝置")

    c = sub.add_parser("calibrate", help="在校準集上擬合 logit 校準與召回率導向門檻")
    c.add_argument("dataset", nargs="?", help="預設為 .env 的 DATASET_DIR")
    c.add_argument("--sample", type=int, help="覆寫 DATASET_SAMPLE_SIZE（0=全部）")

    e = sub.add_parser("evaluate", help="計算混淆矩陣等評分指標")
    e.add_argument("dataset", nargs="?", help="預設為 .env 的 DATASET_DIR")
    e.add_argument("--part", choices=["test", "cal", "all"], default="test")
    e.add_argument("--sample", type=int, help="覆寫 DATASET_SAMPLE_SIZE（0=全部）")
    e.add_argument("--threshold", type=float, help="覆寫決策門檻")
    e.add_argument("--out", default="reports")
    e.add_argument("--no-llm", action="store_true")

    td = sub.add_parser("train-data", help="從訓練集產生微調資料（不需 GPU）")
    td.add_argument("dataset", nargs="?", help="預設為 .env 的 DATASET_DIR")
    td.add_argument("--sample", type=int, help="覆寫 TRAIN_SAMPLE_SIZE（0=全部）")

    t = sub.add_parser("train", help="LoRA / QLoRA 微調（需 NVIDIA GPU）")
    t.add_argument("dataset", nargs="?", help="預設為 .env 的 DATASET_DIR")
    t.add_argument("--sample", type=int, help="覆寫 TRAIN_SAMPLE_SIZE（0=全部）")
    t.add_argument("--rebuild", action="store_true", help="重新產生訓練資料")
    t.add_argument("--resume", action="store_true", help="從上次的 checkpoint 接續訓練")
    t.add_argument("--dry-run", action="store_true", help="只檢查環境、資料與 tokenize，不訓練")
    t.add_argument("--force", action="store_true", help="VRAM 預估不足或沒有 GPU 時仍嘗試")

    x = sub.add_parser("export", help="合併 LoRA 並匯入 Ollama")
    x.add_argument("--no-keep-merged", action="store_true", help="匯入後刪除合併後的模型檔")

    args = ap.parse_args(argv)
    cfg = load_config(args.env)

    if args.cmd in ("train-data", "train", "export"):
        from . import training
        if args.cmd == "train-data":
            training.build_examples(cfg, args.dataset, args.sample)
        elif args.cmd == "train":
            training.train(cfg, args.dataset, args.sample, rebuild=args.rebuild, resume=args.resume,
                           force=args.force, dry_run=args.dry_run)
        else:
            training.export(cfg, keep_merged=not args.no_keep_merged)
        return 0
    hw = cfg["hardware"]
    uses_llm = args.cmd == "hwinfo" or not getattr(args, "no_llm", False)
    if uses_llm:  # 運算資源資訊印到 stderr，不影響 --json 輸出
        _err(f"[運算資源] {hw.summary()}".replace("\n", "\n            "))
        for n in hw.notes:
            _err(f"⚠ {n}")

    if args.cmd == "hwinfo":
        from .llm_check import _chat
        _err(f"\n載入模型 {cfg['ollama']['model']} 中（第一次可能需要數十秒）…")
        try:
            _chat(cfg, [{"role": "user", "content": "hi"}], options={"num_predict": 1})
        except Exception as e:
            _err(f"呼叫 Ollama 失敗：{e}")
            return 1
        _show_placement(cfg)
        return 0

    if args.cmd == "analyze":
        reports = [analyze_file(f, cfg, use_llm=not args.no_llm) for f in args.files]
        if uses_llm:
            _show_placement(cfg)
        if args.json:
            print(json.dumps(reports if len(reports) > 1 else reports[0], default=_jsonable,
                             ensure_ascii=False, indent=2))
        else:
            for r in reports:
                _print_report(r)
        return 0
    if args.cmd == "calibrate":
        from .evaluate import calibrate
        calibrate(cfg, args.dataset, sample=args.sample)
        return 0
    if args.cmd == "evaluate":
        from .evaluate import evaluate
        evaluate(cfg, args.dataset, part=args.part, sample=args.sample, threshold=args.threshold,
                 out_dir=args.out, use_llm=not args.no_llm)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
