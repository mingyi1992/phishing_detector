# 資料集放置處

資料集檔案太大（超過 GitHub 100 MB 單檔上限），不放在 Git 裡，請自行下載：

1. 到 Kaggle 搜尋 **Phishing Email Dataset**（作者 naserabdullahalam，副標「Phish No More」）並下載
2. 解壓縮後，把以下 CSV 放進這個資料夾：

```
dataset/
├── CEAS_08.csv
├── Enron.csv
├── Ling.csv
├── Nazario.csv
├── Nigerian_Fraud.csv
├── SpamAssasin.csv
└── phishing_email.csv   ← 其餘六檔的合併版，預設不使用，可不放
```

要使用哪些檔案由 `.env` 的 `DATASET_FILES` 決定。
