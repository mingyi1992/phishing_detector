# PhishGuard：惡意 / 詐騙郵件偵測

```
.eml ─┬─ image_check.py      圖片 QR Code 解碼、OCR（本機）、純圖片信件
      ├─ url_check.py        網址：非白名單 IP 直接判惡意、顯示/實際網域不符、仿冒網域、短網址…
      ├─ llm_check.py        Ollama SLM：2000 字分段取最高 logit、差異測試、理由
      │  injection_guard.py  提示詞注入防護（隱藏文字、規則偵測、spotlighting）
      ├─ header_check.py     信任邊界、SPF/DKIM/DMARC/ARC、寄件者一致性、同形字仿冒、Received 路徑
      ├─ attachment_check.py 雙副檔名、RTLO、檔頭偽裝、Office 巨集、壓縮檔、本機雜湊比對
      └─ analyzer.py         logistic 融合 → 最終惡意機率 + 判定原因；模型失敗 → 隔離
evaluate.py  混淆矩陣、Recall/Precision/F1/F2、ROC/PR-AUC、Brier、ECE；calibrate 校準與門檻
```

## 重要設定（上線前務必填寫 `.env`）

| 設定 | 作用 |
|---|---|
| `MX_HOSTNAMES` | 我方收信伺服器名稱。Received 中「by 我方 MX」的第一跳是信任邊界，其下的標頭都可能是偽造的 |
| `TRUSTED_AUTHSERV_IDS` | 只採信這些伺服器、且位於邊界之上的 Authentication-Results |
| `data/ip_whitelist.txt` | 連結直接寫 IP 時，只有清單內（可寫 CIDR）的 IP 不會被判為惡意。內網 IP 也要列入，否則內部信件連到內網 IP 會被攔截 |
| `data/url_blocklist.txt` | 離線網址黑名單 |

未設定前兩項時，每封信都會顯示「設定提醒」。

## 判定規則重點

- **模型未成功啟用 → 隔離**：Ollama 未啟動、逾時或錯誤時，信件直接隔離並標註「模型未成功啟用」。
- **分段判讀**：內文、隱藏文字、OCR 文字各切成 2000 字一段（重疊 200 字），每段各自判讀取最高 logit，
  防止「前面塞大量正常內容、詐騙藏在最後」。段數上限 `LLM_MAX_CHUNKS`。
- **差異測試**：把可疑句子（注入規則命中、隱藏文字、「忽略/判定/核准…」＋「AI/系統/安全…」同時出現的句子）
  移除後重判；惡意 logit 上升超過 `INJECTION_DIFF_THRESHOLD` → 確認信件在操控模型。
- **IP 連結**：網址主機直接是 IP（含 `http://3232235777/`、`0xC0A80101` 等混淆寫法，以及跳轉參數中夾帶的 IP 網址），
  不在白名單 → 機率下限 `IP_URL_MIN_PROB`。
- **ARC**：郵件論壇/轉寄造成的 DMARC fail，若 ARC 通過且簽章者在 `ARC_TRUSTED_SEALERS` 內則降低扣分。
- **同形字**：西里爾/希臘字母、`rn→m`、`0→o`、`1→l` 等字元替換的仿冒網域（寄件者與連結皆檢查）。
- **品牌冒用**：`BRAND_KEYWORDS=關鍵字:官方網域|…`，只在顯示名稱「就是品牌」或帶有客服/通知等官方字眼時才計分。

變更判讀方法後（`LLM_VERSION`），舊的快取與 `calibration.json` 會自動失效，需重新執行 calibrate。

- **全部在本機執行**：LLM 走本機 Ollama；雜湊只比對本機清單；不做 DNS、VirusTotal 等任何外部查詢。
- **設定都在 `.env`**（範本 `.env.example`），程式內不寫死；系統環境變數可覆寫 `.env`。
- **以不漏抓為優先**：`calibrate` 會找出達到 `TARGET_RECALL` 的門檻；每封被攔截的信都會列出判定原因
  （各模組貢獻、標頭/附件發現、LLM 理由），方便人工複核誤擋。

## 使用

```bash
pip install -r requirements.txt
copy .env.example .env                 # 修改模型、門檻、資料集路徑等
python tools/make_samples.py           # 產生 8 封示範信
python -m phishguard analyze samples/dataset/phishing/prompt_injection.eml
python -m phishguard analyze mail.eml --json
python -m phishguard calibrate         # 在校準集上擬合 Platt 參數與召回率導向門檻 → calibration.json
python -m phishguard evaluate          # 在測試集上輸出混淆矩陣與各項指標 → reports/
```

## 運算資源（GPU / CPU 自動切換）

`.env` 的 `OLLAMA_DEVICE`：
- `auto`（預設）：偵測到 GPU → 交給 Ollama 依 VRAM 自動分配；沒有 GPU → 只用 CPU
- `gpu`：強制所有層放 GPU（VRAM 不足可能載入失敗）
- `cpu`：強制只用 CPU

```bash
python -m phishguard hwinfo     # 顯示偵測到的 GPU/CPU，並載入模型確認實際在 GPU 還是 CPU
```

執行 analyze / calibrate / evaluate 時也會自動顯示運算資源，以及模型實際載入的比例
（例如「100% GPU」或「70% GPU / 30% CPU」）。有 GPU 卻跑在 CPU 時會出現警告。

在 NVIDIA 顯卡電腦上使用前：安裝最新 NVIDIA 驅動 → 安裝 Ollama → `ollama pull qwen2.5:7b`。
不需另外安裝 CUDA，Ollama 已內建。偵測只呼叫本機的 `nvidia-smi`，不連外。

## 模型微調（選用，需 NVIDIA GPU）

把 SLM 用自己的資料做 LoRA 微調，再匯回 Ollama 使用。訓練格式與推論完全相同
（同一個 system prompt、nonce 邊界、A/B 單 token 問題），只對答案 token 計算 loss，
等於直接優化判讀時用來算 logit 的那個 token；並以「注入擴增」訓練模型抵抗提示詞注入。

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu124
pip install -r requirements-train.txt
```

1. `.env` 設定切分比例，例如 `DATASET_TRAIN_RATIO=0.6`、`DATASET_CAL_RATIO=0.2`（其餘 0.2 為測試集，三者互不重疊）
2. `.env` 設定 `TRAIN_BASE_MODEL`（需與推論模型同系列，例如 `qwen2.5:7b` ↔ `Qwen/Qwen2.5-7B-Instruct`）

```bash
python -m phishguard train-data              # 產生訓練資料（不需 GPU，可先檢查）
python -m phishguard train --dry-run         # 檢查 GPU、VRAM 預估、tokenize
python -m phishguard train                   # 開始訓練；中斷後可加 --resume 接續
python -m phishguard export                  # 合併 LoRA → ollama create
```

之後把 `.env` 的 `OLLAMA_MODEL` 改成 `TRAIN_OLLAMA_NAME`，重新 `calibrate` 與 `evaluate`，
和原模型的報告比較。

| 顯示卡 VRAM | 建議 |
|---|---|
| 6 GB（筆電 RTX 3060） | `Qwen/Qwen2.5-3B-Instruct`、4-bit、`TRAIN_MAX_SEQ_LEN=1536`；推論改用 `qwen2.5:3b` |
| 8–12 GB | 7B、4-bit、序列長度 1536–2048 |
| 16 GB 以上 | 7B、4-bit 或 16-bit LoRA |

- 匯出時在 CPU 合併權重：7B 約需 16 GB RAM、3B 約 7 GB。
- 若 `ollama create` 無法直接匯入，下載 llama.cpp 原始碼並設定 `LLAMA_CPP_DIR`，會改用 llama.cpp 轉成 GGUF。
- 唯一的外部連線是第一次從 HuggingFace 下載基底模型；`TRAIN_BASE_MODEL` 也可填本機路徑。

## 資料集：Kaggle「Phish No More」

`.env` 的 `DATASET_DIR` 指向解壓縮後的目錄，預設使用
`CEAS_08, Enron, Ling, Nazario, Nigerian_Fraud, SpamAssasin` 六個 CSV（跨檔去重）。
`phishing_email.csv` 是這六檔的合併版，預設不使用。

- **label=1 包含一般垃圾信（spam）**，不只釣魚信，因此 LLM 的判斷問題已涵蓋 spam。
- CSV 只有寄件者、主旨、內文，**沒有驗證標頭、Received、附件**，所以資料集主要用來校準與評估 LLM，
  以及整體決策門檻；標頭與附件權重維持 `.env` 的專家設定。
- 校準集 / 測試集以內容雜湊固定切分（`DATASET_CAL_RATIO`），兩者永不重疊。
- 每次依「來源檔 × 標記」分層抽樣 `DATASET_SAMPLE_SIZE` 封。本機 7B 模型約 5–10 秒/封，
  1000 封約 1.5–3 小時；結果快取在 `cache/`，中斷後重跑會接續。

## logit 校準

1. 要求模型只輸出 1 個 token（A/B），用 Ollama `logprobs` 取得 top-20 對數機率。
2. `raw_logit = logP(惡意) − logP(正常)`；對調 A/B 選項再問一次並平均，消除字母與位置偏誤。
3. Platt scaling：`p = sigmoid(a·raw_logit + b)`，a、b 由 `calibrate` 在校準集上擬合。
4. 融合：`final = sigmoid(BIAS + W_LLM·LLM校準logit + W_HEADER·標頭 + W_ATTACHMENT·附件 + W_INJECTION·注入)`。
5. 門檻：校準集上「召回率 ≥ TARGET_RECALL」的最高門檻。

## 提示詞注入防護

| 層 | 作法 |
|---|---|
| 正規化 | NFKC、移除零寬與 Bidi 控制字元，避免拆字繞過 |
| HTML 清洗 | 隱藏文字（display:none、font-size:0、白字、註解）獨立抽出並標示為「收件者看不到」 |
| 規則偵測 | 中英文注入語句、偽造 system/assistant、`<\|im_start\|>`、`[INST]` 等 |
| Spotlighting | 每次隨機 nonce 邊界包住信件；中和內容中偽造的邊界與標記 |
| System prompt | 聲明邊界內為不可信資料；注入企圖本身視為惡意證據；任務在內容後重述 |
| 輸出限制 | 分類只取 1 個 token 的 logprob；理由用 JSON schema 限制格式 |
| 決策隔離 | 偵測到注入 → 機率下限 `INJECTION_MIN_PROB`，LLM 被說服也無法翻盤 |

## 已知惡意雜湊

`MALWARE_HASH_DB`（預設 `data/malware_hashes.txt`）：md5 / sha1 / sha256 一行一個，
也可直接放離線下載的 MalwareBazaar CSV。程式不會連線查詢。
