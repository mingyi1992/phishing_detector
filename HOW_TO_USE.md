# PhishGuard 操作手冊

本文件說明：
- **第一部分**：資料要放在哪、怎麼分析信件、怎麼評估準確度
- **第二部分**：怎麼微調（訓練）模型

所有指令都在專案資料夾 `phishing_detector` 內執行（PowerShell 或命令提示字元皆可）。

---

## 0. 第一次使用前的準備

### 在新電腦從 GitHub 下載

```bash
git clone https://github.com/mingyi1992/phishing_detector.git
```

```bash
cd phishing_detector
```

Git 裡**沒有**以下檔案，需要在新電腦自行準備：

| 檔案 | 做法 |
|---|---|
| `.env` | `copy .env.example .env`，再依需要修改 |
| `dataset/*.csv` | 從 Kaggle 下載，見 [dataset/README.md](dataset/README.md) |
| `calibration.json`、`cache/`、`reports/` | 執行 `calibrate` / `evaluate` 時自動產生（每台電腦、每個模型要自己跑） |

接著依下表完成安裝。

| 步驟 | 指令 / 動作 |
|---|---|
| 1. 安裝 Python 3.10 以上 | https://www.python.org |
| 2. 安裝 Ollama | https://ollama.com ，安裝後系統匣會出現 Ollama 圖示（代表在背景執行） |
| 3. 下載模型 | `ollama pull qwen2.5:7b` |
| 4. 安裝套件 | `pip install -r requirements.txt` |
| 5. 建立設定檔 | `copy .env.example .env`（已經有 `.env` 就跳過） |
| 6. 確認運算資源 | `python -m phishguard hwinfo` |

第 6 步應看到「模型實際載入：100% GPU」（有 NVIDIA 顯示卡時）或「100% CPU」（沒有顯示卡時）。

---

# 第一部分：資料放置與使用

## 1-1. 資料夾結構

```
phishing_detector/
├── .env                      ← 所有設定（模型、門檻、路徑…）
├── data/
│   ├── ip_whitelist.txt      ← IP 白名單（你要維護）
│   ├── url_blocklist.txt     ← 網址黑名單（選用）
│   └── malware_hashes.txt    ← 已知惡意檔雜湊（選用）
├── dataset/                  ← 評估 / 訓練用資料集
│   ├── CEAS_08.csv
│   ├── Enron.csv
│   └── …（Kaggle 下載的 CSV）
├── samples/dataset/          ← 內建示範信（phishing/、legit/）
├── reports/                  ← evaluate 產生的報告與圖表
├── cache/                    ← LLM 結果快取（可刪，刪了會重算）
├── calibration.json          ← calibrate 產生的校準參數
└── models/finetune/          ← 訓練產生的模型檔
```

## 1-2. 要分析的信件（.eml）

信件可以放在**任何位置**，執行時給路徑即可。建議另外建一個資料夾，例如 `inbox/`。

**怎麼取得 .eml 檔：**

| 郵件軟體 | 做法 |
|---|---|
| Gmail（網頁） | 開啟信件 → 右上「⋮」→「顯示原始郵件」→「下載原始郵件」 |
| Outlook 網頁版 / 新版 Outlook | 開啟信件 → 「…」→「下載」（存成 .eml） |
| 傳統版 Outlook（桌面） | 「另存新檔」預設是 **.msg**，本程式**不支援**；請改用 Outlook 網頁版下載 |
| Thunderbird | 選取信件 → 「另存為」→ 檔案 |

> ⚠ 請用「下載原始郵件」的方式取得。用「轉寄」得到的信件，標頭已被改寫，標頭檢查會失準。

## 1-3. 分析信件

```bash
python -m phishguard analyze inbox/信件.eml
```

一次分析多封：

```bash
python -m phishguard analyze inbox/a.eml inbox/b.eml inbox/c.eml
```

其他選項：

| 選項 | 用途 |
|---|---|
| `--json` | 輸出 JSON（方便給其他程式使用） |
| `--no-llm` | 只跑規則檢查、不呼叫模型（很快，但不完整） |

**報告怎麼看：**

```
▶ 判定：惡意/詐騙（攔截）    惡意機率 = 0.9724   門檻 0.300
  判定原因：
   • 各模組對 logit 的貢獻：…        ← 哪個模組影響最大
   • [header] …                       ← 具體證據，依嚴重程度排序
   • [LLM] …                          ← 模型給的理由
[1] 標頭檢查  [2] 網址分析  [3] 圖片分析  [4] SLM 內容判讀  [5] 附件檢查
```

| 判定 | 意義 |
|---|---|
| 惡意/詐騙（攔截） | 機率 ≥ 0.8 |
| 可疑（攔截，建議人工複核） | 機率 ≥ 門檻 |
| 低風險（放行，仍請留意） | 機率介於門檻的一半和門檻之間 |
| 正常 | 機率 < 門檻的一半 |
| 隔離（模型未成功啟用） | Ollama 沒開或出錯；請啟動 Ollama 後重新分析 |

## 1-4. 上線前必填的設定（`.env`）

### (a) 信任邊界：`MX_HOSTNAMES`、`TRUSTED_AUTHSERV_IDS`

這兩項決定程式「相信哪些標頭」。不填也能跑，但每封信都會出現「設定提醒」，偽造的標頭也比較難識破。

**怎麼找：** 用 1-2 的方式下載一封**外部寄來的**信件，用記事本打開，找以下兩種標頭：

```
Received: from mail.sender.com (...[203.0.113.5]) by mx.google.com with ESMTPS ...
                                                    ^^^^^^^^^^^^^ 這是你的收信伺服器
Authentication-Results: mx.google.com; spf=pass ...
                        ^^^^^^^^^^^^^ 這是 authserv-id
```

| 你的信箱服務 | 建議設定 |
|---|---|
| Gmail / Google Workspace | `MX_HOSTNAMES=mx.google.com`<br>`TRUSTED_AUTHSERV_IDS=mx.google.com` |
| Microsoft 365 / Outlook.com | `MX_HOSTNAMES=prod.outlook.com`（會比對所有 `*.prod.outlook.com`）<br>`TRUSTED_AUTHSERV_IDS=` **留空**（Microsoft 的驗證標頭沒有 authserv-id 欄位） |
| 公司自建郵件伺服器 | 依標頭中實際看到的主機名稱填寫 |

### (b) IP 白名單：`data/ip_whitelist.txt`

信件中的連結若**直接寫 IP**（例如 `http://203.0.113.5/login`），只要不在白名單內就判定為惡意。
公司內網、合作廠商的伺服器 IP 請加進來，一行一筆，可寫網段：

```
10.0.0.0/8            # 公司內網
192.168.0.0/16
203.0.113.10          # 合作廠商的報表伺服器
```

### (c) 其他清單（選用）

| 檔案 | 格式 |
|---|---|
| `data/url_blocklist.txt` | 一行一個網域或完整網址 |
| `data/malware_hashes.txt` | 一行一個 md5 / sha1 / sha256，也可直接放 MalwareBazaar 下載的 CSV |

## 1-5. 評估準確度（資料集）

### 放置資料集

**方式 A：Kaggle「Phish No More」**（目前使用中）
1. 從 Kaggle 下載 *Phishing Email Dataset*（作者 naserabdullahalam），解壓縮
2. 把 CSV 檔放進 `dataset/`
3. `.env` 的 `DATASET_DIR=dataset`、`DATASET_FILES=` 列出要用的檔名

**方式 B：自己的 .eml 信件**

```
my_dataset/
├── phishing/    ← 惡意信 .eml（可再分子資料夾）
└── legit/       ← 正常信 .eml
```

執行時把路徑加在指令後面，例如 `python -m phishguard evaluate my_dataset`。

> 資料會依內容自動、固定地切成「校準集」和「測試集」（比例 `DATASET_CAL_RATIO`），兩者不重疊。

### 執行

```bash
python -m phishguard calibrate --sample 1000
```

```bash
python -m phishguard evaluate --sample 1000
```

| 步驟 | 作用 | 產出 |
|---|---|---|
| `calibrate` | 在校準集上算出機率校準參數，以及達到目標召回率（`TARGET_RECALL`）的門檻 | `calibration.json` |
| `evaluate` | 在測試集上計算混淆矩陣、Recall、Precision、F1/F2、ROC-AUC 等 | `reports/metrics.json`、`reports/evaluation.png` |

- `--sample` 是抽樣封數。CPU 每封約 30–40 秒，GPU 每封約 1–3 秒。
- 中斷後重新執行同一個指令會從斷點接續（結果快取在 `cache/`）。
- **換模型、或修改判讀相關設定後，要重新執行 `calibrate`。**

---

# 第二部分：訓練（微調）模型

## 2-1. 訓練與使用的關係

```
訓練（HuggingFace，需要 GPU）            使用（Ollama，和平常一樣）
train → LoRA adapter → export ───────▶  Ollama 模型「phishguard-qwen2.5」
                                          → analyze / calibrate / evaluate
```

訓練完成後模型會匯入 Ollama，**之後的使用方式和第一部分完全相同**，只是 `.env` 的 `OLLAMA_MODEL` 換成新模型。

## 2-2. 硬體需求

| 項目 | 需求 |
|---|---|
| 顯示卡 | NVIDIA，並安裝最新驅動程式 |
| VRAM 6 GB（例：筆電 RTX 3060） | 只能訓練 **3B** 模型 |
| VRAM 8–12 GB | 可訓練 7B（4-bit） |
| 系統記憶體（匯出時用） | 7B 約 16 GB、3B 約 7 GB |
| 硬碟 | 7B 約 30 GB、3B 約 15 GB（基底模型＋合併後模型＋匯出檔） |

## 2-3. 安裝訓練套件（只需一次）

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu124
```

```bash
pip install -r requirements-train.txt
```

確認 torch 有抓到顯示卡（應顯示 `True`）：

```bash
python -c "import torch; print(torch.cuda.is_available())"
```

## 2-4. 修改 `.env`

**(1) 資料切分**：切出訓練集，三者互不重疊

```
DATASET_TRAIN_RATIO=0.6     # 訓練集
DATASET_CAL_RATIO=0.2       # 校準集（其餘 0.2 為測試集）
```

> ⚠ 改了比例之後，校準集和測試集的組成會改變，舊的 `calibration.json` 與報告不能再拿來比較。

**(2) 基底模型**：要和推論用的模型同系列

| 顯示卡 | `TRAIN_BASE_MODEL` | `TRAIN_MAX_SEQ_LEN` | 推論模型（訓練前比較用） |
|---|---|---|---|
| 6 GB | `Qwen/Qwen2.5-3B-Instruct` | `1536` | `qwen2.5:3b`（先 `ollama pull qwen2.5:3b`） |
| 8 GB 以上 | `Qwen/Qwen2.5-7B-Instruct` | `2048` | `qwen2.5:7b` |

**(3) 其他常用設定**

| 設定 | 預設 | 說明 |
|---|---|---|
| `TRAIN_SAMPLE_SIZE` | 4000 | 從訓練集抽幾封信 |
| `TRAIN_EPOCHS` | 1 | 訓練回合數 |
| `TRAIN_INJECTION_AUG` | 0.3 | 30% 的信額外產生一份「插入注入語句」的版本，訓練模型不被操控 |
| `TRAIN_OLLAMA_NAME` | phishguard-qwen2.5 | 匯入 Ollama 後的模型名稱 |

## 2-5. 訓練步驟

**步驟 1：訓練前先記錄原模型的成績（作為比較基準）**

```bash
python -m phishguard calibrate
```

```bash
python -m phishguard evaluate --out reports/before
```

**步驟 2：產生訓練資料**（不需 GPU，可先確認數量和比例）

```bash
python -m phishguard train-data
```

**步驟 3：檢查環境**（GPU、VRAM 預估、資料長度，不會真的訓練）

```bash
python -m phishguard train --dry-run
```

若顯示「VRAM 可能不足」，請依 2-4 換成較小的模型或降低 `TRAIN_MAX_SEQ_LEN`。

**步驟 4：先用少量資料試跑整個流程**（建議第一次一定要做）

```bash
python -m phishguard train --sample 100 --rebuild
```

**步驟 5：正式訓練**

```bash
python -m phishguard train --rebuild
```

- 第一次會從 HuggingFace 下載基底模型（數 GB）。
- 中斷後加 `--resume` 可從上次的進度接續。
- 完成後會顯示「驗證集答案正確率」，結果存在 `models/finetune/adapter/`。

**步驟 6：匯出到 Ollama**

```bash
python -m phishguard export
```

確認清單中出現新模型：

```bash
ollama list
```

**步驟 7：切換到新模型並重新校準、評估**

`.env` 改成：

```
OLLAMA_MODEL=phishguard-qwen2.5
```

```bash
python -m phishguard hwinfo
```

```bash
python -m phishguard calibrate
```

```bash
python -m phishguard evaluate --out reports/after
```

**步驟 8：比較成效**

比較 `reports/before/` 和 `reports/after/` 的 `metrics.json`、`evaluation.png`，重點看：
- **Recall**（漏抓率越低越好）
- **FPR**（誤擋率）
- **ROC-AUC**（整體區分能力）

新模型比較差的話，把 `OLLAMA_MODEL` 改回原本的模型即可，兩者會同時存在於 Ollama。

## 2-6. 在 A 電腦訓練、B 電腦使用

1. 在 A 電腦完成步驟 1–6
2. 把 `models/finetune/merged/` 資料夾和 `models/finetune/Modelfile` 複製到 B 電腦
3. 用記事本打開 `Modelfile`，把第一行 `FROM` 後面的路徑改成 B 電腦上 `merged` 資料夾的位置
4. 在 B 電腦執行：
   ```bash
   ollama create phishguard-qwen2.5 -f Modelfile
   ```
5. 在 B 電腦做步驟 7（**校準要在 B 電腦重新做**）

---

## 常見問題

| 狀況 | 處理方式 |
|---|---|
| 判定顯示「隔離（模型未成功啟用）」 | Ollama 沒在執行，或模型名稱打錯。確認系統匣有 Ollama 圖示，並執行 `ollama list` 確認名稱 |
| 每封信都出現「設定提醒」 | 填寫 `.env` 的 `MX_HOSTNAMES`（見 1-4） |
| 內部信件被判惡意，原因是「連結直接使用 IP」 | 把該 IP 或網段加入 `data/ip_whitelist.txt` |
| 顯示「calibration.json … 已忽略」 | 換過模型或更新過程式，請重新執行 `calibrate` |
| `hwinfo` 顯示有 GPU 但模型跑在 CPU | 更新 NVIDIA 驅動程式，並重新啟動 Ollama |
| `hwinfo` 顯示部分在 GPU、部分在 CPU | VRAM 不足：降低 `.env` 的 `OLLAMA_NUM_CTX`（例如 4096），或改用較小的模型 |
| 圖片分析顯示「未安裝…」 | `pip install opencv-python-headless rapidocr_onnxruntime` |
| 訓練時顯示「缺少訓練套件」 | 依 2-3 安裝 |
| 訓練時顯示「VRAM 可能不足」 | 改用 3B 模型、降低 `TRAIN_MAX_SEQ_LEN` |
| 訓練中途出現 `CUDA out of memory` | 降低 `TRAIN_MAX_SEQ_LEN`，或確認 `TRAIN_BATCH_SIZE=1` |
| `export` 時 `ollama create` 失敗 | 下載 llama.cpp 原始碼，在 `.env` 設定 `LLAMA_CPP_DIR=該資料夾路徑` 後重試 |

## 指令總覽

| 指令 | 用途 |
|---|---|
| `python -m phishguard hwinfo` | 檢查 GPU / CPU 與模型載入狀態 |
| `python -m phishguard analyze 信件.eml` | 分析信件 |
| `python -m phishguard calibrate` | 校準機率與門檻 |
| `python -m phishguard evaluate` | 計算混淆矩陣等指標 |
| `python -m phishguard train-data` | 產生訓練資料 |
| `python -m phishguard train` | 微調模型（`--dry-run` / `--sample N` / `--resume` / `--rebuild`） |
| `python -m phishguard export` | 匯出到 Ollama |
| `python tools/make_samples.py` | 重新產生示範信件 |
