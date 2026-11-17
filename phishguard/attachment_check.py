"""(3) 附件檢查：雙副檔名、危險副檔名、檔頭偽裝、Office 巨集、壓縮檔內容、雜湊值比對已知惡意檔。

雜湊比對只查本機清單（.env 的 MALWARE_HASH_DB），不做任何外部連線。
清單可放 md5 / sha1 / sha256，一行一個，也可直接放 MalwareBazaar 等來源離線下載的 CSV。
"""
from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import zipfile
from functools import lru_cache
from pathlib import Path

from .common import Finding
from .parser import ParsedEmail

M = "attachment"

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "msi", "msp", "ps1", "psm1", "jar", "lnk", "cpl", "dll", "reg", "sct", "inf", "gadget",
    "application", "appx", "msix", "appref-ms", "xll", "chm", "url", "scf", "iqy", "slk",
}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "one", "zip", "rar", "7z", "cab", "gz", "tar", "ace", "arj"}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"}
LEGACY_OFFICE_EXT = {"doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif",
             "rtf", "csv", "odt", "mp3", "mp4", "zip", "html", "htm"}
HTML_EXT = {"html", "htm", "shtml", "svg", "xhtml"}

SUSPICIOUS_VBA = ["AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open", "AutoExec", "Shell",
                  "WScript.Shell", "CreateObject", "URLDownloadToFile", "XMLHTTP", "Powershell",
                  "cmd.exe", "Chr(", "StrReverse", "CallByName", "Environ", "ADODB.Stream"]


def _magic(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:5] == b"{\\rtf":
        return "rtf"
    if data[:4] == b"Rar!":
        return "rar"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:4] == b"L\x00\x00\x00":
        return "lnk"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    return "unknown"


_EXPECTED_MAGIC = {"pdf": {"pdf"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "png": {"png"},
                   "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "zip": {"zip"},
                   "doc": {"ole", "rtf"}, "xls": {"ole"}, "ppt": {"ole"}, "rtf": {"rtf"},
                   "txt": {"unknown"}, "csv": {"unknown"}}


# ---------------------------------------------------------------- 檔名檢查

def check_filename(name: str, findings: list[Finding]) -> list[str]:
    if any(ch in name for ch in "‮‭‏‎⁦⁧⁨"):
        findings.append(Finding(M, "RTLO_FILENAME", 4.0,
                                f"檔名含 Unicode 方向控制字元（RTLO 偽裝），實際檔名：{name!r}"))
    clean = unicodedata.normalize("NFKC", name).translate(
        dict.fromkeys(map(ord, "‮‭‏‎⁦⁧⁨​"), None))
    clean = clean.strip().rstrip(". ").lower()
    exts = [e.strip() for e in clean.split(".")[1:]]
    last = exts[-1] if exts else ""

    if len(exts) >= 2 and exts[-2] in DECOY_EXT and (last in EXECUTABLE_EXT or last in CONTAINER_EXT - {"zip"}):
        findings.append(Finding(M, "DOUBLE_EXTENSION", 4.0,
                                f"雙副檔名偽裝：{name}（看似 .{exts[-2]}，實為 .{last}）"))
    elif re.search(r"\.(%s)\s{3,}\.\w+$" % "|".join(DECOY_EXT), clean):
        findings.append(Finding(M, "PADDED_EXTENSION", 4.0, f"以大量空白隱藏真正副檔名：{name}"))

    if last in EXECUTABLE_EXT:
        findings.append(Finding(M, "EXECUTABLE_ATTACHMENT", 3.0, f"可執行/腳本類附件：{name}"))
    elif last in CONTAINER_EXT - {"zip"}:
        findings.append(Finding(M, "DISK_IMAGE_OR_ARCHIVE", 1.5, f"映像檔/壓縮檔附件（常用來繞過 MOTW）：{name}"))
    elif last in HTML_EXT:
        findings.append(Finding(M, "HTML_ATTACHMENT", 1.5, f"HTML/SVG 附件（常見於釣魚登入頁）：{name}"))
    if last in MACRO_EXT:
        findings.append(Finding(M, "MACRO_ENABLED_EXT", 2.0, f"啟用巨集格式的 Office 檔：{name}"))
    return exts


# ---------------------------------------------------------------- 巨集檢查

def _structural_macro_check(data: bytes) -> tuple[bool, list[str]]:
    """不依賴 oletools 的結構檢查：OOXML 內有 vbaProject.bin / macrosheets，或 OLE 內有 VBA 儲存區。"""
    kind = _magic(data)
    found, vba_code = False, b""
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    if n.lower().endswith("vbaproject.bin") or "/macrosheets/" in n.lower():
                        found = True
                        if n.lower().endswith(".bin"):
                            vba_code += z.read(n)[: 5 * 2**20]
        except (zipfile.BadZipFile, RuntimeError):
            pass
    elif kind == "ole":
        if b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data or b"Macros" in data:
            found, vba_code = True, data
    low = vba_code.lower()
    return found, [k for k in SUSPICIOUS_VBA if k.lower().encode() in low] if vba_code else []


def check_macros(name: str, data: bytes, findings: list[Finding]) -> dict:
    info = {"has_macros": False, "method": [], "suspicious_keywords": []}
    kws: set[str] = set()
    try:
        from oletools.olevba import VBA_Parser  # type: ignore

        vp = VBA_Parser(name, data=data)
        if vp.detect_vba_macros():
            info["has_macros"] = True
            info["method"].append("oletools")
            kws |= {kw for typ, kw, _ in vp.analyze_macros() if typ in ("AutoExec", "Suspicious", "IOC")}
        vp.close()
    except ImportError:
        pass
    except Exception as e:  # 檔案損毀或刻意變形：oletools 解析失敗本身也值得注意
        info["error"] = str(e)[:200]
    # 結構檢查一律執行：oletools 解析失敗或判斷不到時仍能抓到
    found, skw = _structural_macro_check(data)
    if found:
        info["has_macros"] = True
        info["method"].append("structure")
        kws |= set(skw)
    info["suspicious_keywords"] = sorted(kws)[:20]

    if info["has_macros"]:
        auto = [k for k in info["suspicious_keywords"] if "open" in k.lower() or "auto" in k.lower()]
        pts = 3.0 + (1.5 if auto else 0) + (1.0 if len(info["suspicious_keywords"]) >= 3 else 0)
        findings.append(Finding(M, "OFFICE_MACRO", pts,
                                f"{name} 含 VBA/XLM 巨集" +
                                (f"，可疑關鍵字：{', '.join(info['suspicious_keywords'][:8])}" if info["suspicious_keywords"] else "")))
    return info


# ---------------------------------------------------------------- 雜湊查詢

@lru_cache(maxsize=1)
def _local_hashes(path: str) -> frozenset[str]:
    p = Path(path)
    if not p.exists():
        return frozenset()
    out = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith("#"):
            continue
        for tok in re.split(r"[\s,\"]+", line):  # 支援 MalwareBazaar CSV（第二欄為 sha256）
            if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", tok):
                out.add(tok.lower())
    return frozenset(out)


def check_hash(name: str, data: bytes, cfg: dict, findings: list[Finding]) -> dict:
    hashes = {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
              "sha256": hashlib.sha256(data).hexdigest()}
    db = _local_hashes(cfg["attachment"]["local_hash_db"])
    result = {"hashes": hashes, "hash_db_size": len(db),
              "known_malicious": any(h in db for h in hashes.values())}
    if result["known_malicious"]:
        findings.append(Finding(M, "KNOWN_MALWARE_HASH", 10.0,
                                f"{name} 的雜湊值符合已知惡意檔（sha256={hashes['sha256'][:16]}…）"))
    return result


# ---------------------------------------------------------------- 入口

def _inspect_zip(name: str, data: bytes, findings: list[Finding]) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
    except zipfile.BadZipFile:
        return []
    if any(i.flag_bits & 0x1 for i in infos):
        findings.append(Finding(M, "ENCRYPTED_ARCHIVE", 2.0, f"{name} 為加密壓縮檔（防毒無法掃描，常見於惡意郵件）"))
    names = [i.filename for i in infos]
    for inner in names[:50]:
        sub: list[Finding] = []
        check_filename(inner.rsplit("/", 1)[-1], sub)
        for f in sub:
            findings.append(Finding(M, "ARCHIVE_" + f.code, f.points * 0.9, f"壓縮檔 {name} 內：{f.message}"))
    return names[:50]


def analyze_attachments(pe: ParsedEmail, cfg: dict) -> dict:
    findings: list[Finding] = []
    items = []
    for att in pe.attachments:
        exts = check_filename(att.filename, findings)
        last = exts[-1] if exts else ""
        magic = _magic(att.data)
        item = {"filename": att.filename, "content_type": att.content_type, "size": len(att.data),
                "magic": magic}
        if magic in ("pe", "elf") and last not in EXECUTABLE_EXT:
            findings.append(Finding(M, "MAGIC_MISMATCH", 4.0,
                                    f"{att.filename} 副檔名為 .{last}，但檔頭是可執行檔（{magic.upper()}）"))
        elif last in _EXPECTED_MAGIC and magic not in _EXPECTED_MAGIC[last] and magic != "unknown":
            findings.append(Finding(M, "MAGIC_MISMATCH", 1.5,
                                    f"{att.filename} 副檔名 .{last} 與實際檔案格式 {magic} 不符"))
        if last in MACRO_EXT | LEGACY_OFFICE_EXT | {"docx", "xlsx", "pptx", "rtf"} or magic in ("ole", "zip") \
                and last not in {"zip", "jar", "apk"}:
            item["macro"] = check_macros(att.filename, att.data, findings)
        if magic == "zip" and last in {"zip", "jar"}:
            item["archive_entries"] = _inspect_zip(att.filename, att.data, findings)
        item.update(check_hash(att.filename, att.data, cfg, findings))
        items.append(item)
    score = sum(f.points for f in findings)
    return {"score": round(score, 2), "count": len(items), "items": items,
            "known_malicious": any(i["known_malicious"] for i in items), "findings": findings}
