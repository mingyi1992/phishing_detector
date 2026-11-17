"""共用資料結構與工具。"""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import asdict, dataclass

# 常見二級公共後綴（未安裝 tldextract 時的簡易組織網域判斷）
_TWO_LEVEL_SUFFIXES = {
    "com.tw", "org.tw", "gov.tw", "edu.tw", "net.tw", "idv.tw",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "org.hk", "com.au",
    "net.au", "org.au", "co.kr", "com.sg", "com.my", "co.nz", "com.br",
}

try:
    import tldextract  # type: ignore

    _TLD = tldextract.TLDExtract(suffix_list_urls=())  # 只用內建清單，不連網
except Exception:  # pragma: no cover
    _TLD = None


@dataclass
class Finding:
    module: str      # header / llm / attachment / injection
    code: str        # 機器可讀代碼
    points: float    # 風險分數（越高越可疑，負值代表加分項）
    message: str     # 人可讀說明

    def to_dict(self):
        return asdict(self)


def org_domain(domain: str | None) -> str:
    """取得組織網域（例如 mail.ctbcbank.com.tw -> ctbcbank.com.tw）。"""
    if not domain:
        return ""
    domain = domain.strip().strip(".").lower()
    if _TLD is not None:
        ext = _TLD(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_ADDR_RE = re.compile(r"[\w.+'-]+@([\w-]+(?:\.[\w-]+)+)", re.UNICODE)


def domain_of(addr: str | None) -> str:
    if not addr:
        return ""
    m = _ADDR_RE.search(addr)
    return m.group(1).lower() if m else ""


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def logit(p: float, eps: float = 1e-6) -> float:
    p = min(max(p, eps), 1 - eps)
    return math.log(p / (1 - p))


# ---------------------------------------------------------------- 同形字（homoglyph）

# 精簡版 Unicode TR39 confusables：常見用來仿冒拉丁字母的字元 → 拉丁字母
_CONFUSABLES = {
    # 西里爾字母
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t",
    "у": "y", "х": "x", "ԝ": "w", "ү": "y", "ɡ": "g",
    # 希臘字母
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    # 其他
    "ı": "i", "ł": "l", "ø": "o", "ß": "b", "ɑ": "a", "ʀ": "r", "ⅼ": "l", "ⅰ": "i",
}
# 多字元與數字混淆（rn→m、vv→w、cl→d、0→o、1→l、3→e、5→s）
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("|", "l")]


def idna_decode(host: str) -> str:
    """xn-- Punycode → Unicode（解碼失敗時原樣回傳）。"""
    labels = []
    for lab in (host or "").lower().split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab[4:].encode("ascii").decode("punycode")
            except Exception:
                pass
        labels.append(lab)
    return ".".join(labels)


def skeleton(text: str) -> str:
    """把字串轉成「長得像什麼」的骨架，用來比對同形字仿冒。"""
    s = unicodedata.normalize("NFKC", text.lower())
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))  # 去掉重音符號 é→e
    for a, b in _MULTI:
        s = s.replace(a, b)
    return s


def scripts_of(text: str) -> set[str]:
    """回傳字串中出現的文字系統（LATIN / CYRILLIC / GREEK / CJK …），忽略數字與符號。"""
    out = set()
    for ch in text:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            out.add("CJK" if name.startswith(("CJK", "HIRAGANA", "KATAKANA", "HANGUL")) else name.split()[0])
    return out


# ---------------------------------------------------------------- IP 解析（含混淆寫法）

def parse_ip_host(host: str):
    """把網址主機名稱解析成 IP；支援 http://3232235777、0xC0A80101、0300.0250.1.1 等混淆寫法。
    不是 IP 時回傳 None。"""
    import ipaddress

    host = (host or "").strip().strip("[]").rstrip(".")
    if not host:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        try:
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", p):
                nums.append(int(p, 16))
            elif re.fullmatch(r"0[0-7]+", p):
                nums.append(int(p, 8))
            elif re.fullmatch(r"\d+", p):
                nums.append(int(p, 10))
            else:
                return None
        except ValueError:
            return None
    # inet_aton 規則：最後一段吃掉剩餘位元
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (4 - len(head)) + last
    return ipaddress.IPv4Address(value)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
