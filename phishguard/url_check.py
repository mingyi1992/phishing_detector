"""網址分析（全部離線）。

來源：HTML 連結 href、<form action>、圖片 QR Code 解出的網址、純文字中的 http(s) 網址，
以及上述網址查詢參數中夾帶的跳轉網址（open redirect，例如 ?url=http://1.2.3.4/）。

規則：
  * 網址主機直接寫 IP（含 3232235777、0xC0A80101、0300.0250.1.1 等混淆寫法），且不在
    IP 白名單（IP_WHITELIST_FILE，支援 CIDR）→ 直接判定為惡意郵件（機率下限 IP_URL_MIN_PROB）
  * 顯示文字是網址/網域，但與實際 href 網域不同
  * 網址含帳密段（https://www.bank.com@evil.com/）
  * Punycode、混用文字系統、同形字 / 拼字近似 / 品牌嵌入子網域的仿冒網域
  * 短網址、可疑頂級網域、非標準埠、javascript: / data: 連結、信件內嵌表單
  * 離線網址黑名單（URL_BLOCKLIST_FILE）
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from .common import Finding, idna_decode, org_domain, parse_ip_host
from .header_check import domain_spoof_findings
from .injection_guard import html_to_text, normalize
from .parser import ParsedEmail

M = "url"

_TEXT_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`）)\]】，。、]+")
_DOMAINISH = re.compile(r"(?i)^(?:https?://)?(?:www\.)?([a-z0-9\-¡-￿]+(?:\.[a-z0-9\-¡-￿]+)+)")
_LOGIN_WORDS = re.compile(r"(?i)login|signin|sign-in|verify|account|update|secure|password|banking|wallet|認證|登入|驗證")


# ---------------------------------------------------------------- 清單檔

def _read_list(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


@lru_cache(maxsize=4)
def load_ip_whitelist(path: str) -> tuple:
    nets = []
    for item in _read_list(path):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(nets)


@lru_cache(maxsize=4)
def load_blocklist(path: str) -> frozenset[str]:
    return frozenset(i.lower().rstrip("/") for i in _read_list(path))


def ip_whitelisted(ip, nets) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


# ---------------------------------------------------------------- 網址收集

def _html_extras(html: str) -> list[tuple[str, str, str]]:
    out = []
    for m in re.finditer(r"(?is)<form\b[^>]*?\baction\s*=\s*[\"']?([^\"'\s>]+)", html or ""):
        out.append((m.group(1), "", "form"))
    for m in re.finditer(r"(?is)<(?:iframe|frame|meta)\b[^>]*?(?:src|url)\s*=\s*[\"']?([^\"'\s>;]+)", html or ""):
        out.append((m.group(1), "", "embed"))
    return out


def collect_urls(pe: ParsedEmail, extra: list[tuple[str, str, str]] = ()) -> list[dict]:
    """回傳 [{url, text, source}]，source ∈ href/form/embed/text/qr/redirect。"""
    seen, out = set(), []

    def add(url, text, source):
        url = (url or "").strip()
        if not url or url.startswith(("#", "mailto:", "tel:", "cid:")):
            return
        key = (url, source)
        if key in seen:
            return
        seen.add(key)
        out.append({"url": url, "text": text, "source": source})
        # 查詢參數與片段中夾帶的跳轉網址（最多解兩層編碼）
        try:
            parts = urlsplit(url)
            for _, v in parse_qsl(parts.query, keep_blank_values=True) + [("", parts.fragment)]:
                v = unquote(unquote(v))
                for m in _TEXT_URL.finditer(v):
                    add(m.group(0), "", "redirect")
        except ValueError:
            pass

    if pe.html:
        _, _, links = html_to_text(pe.html)
        for href, text in links:
            add(href, normalize(text), "href")
        for u, t, s in _html_extras(pe.html):
            add(u, t, s)
    for m in _TEXT_URL.finditer(pe.text or ""):
        add(m.group(0), "", "text")
    for u, t, s in extra:
        add(u, t, s)
    return out


# ---------------------------------------------------------------- 分析

def _host_of(url: str) -> tuple[str, str, bool, int | None]:
    """回傳 (scheme, host, 是否含帳密段, port)。"""
    try:
        p = urlsplit(url if "://" in url else "http://" + url)
        port = p.port
    except ValueError:
        return "", "", False, None
    return p.scheme.lower(), (p.hostname or "").lower(), "@" in (p.netloc or ""), port


def analyze_urls(pe: ParsedEmail, cfg: dict, extra: list[tuple[str, str, str]] = ()) -> dict:
    ucfg = cfg["url"]
    nets = load_ip_whitelist(ucfg["ip_whitelist_file"])
    blocklist = load_blocklist(ucfg["blocklist_file"])
    shorteners = {s.lower() for s in ucfg["shorteners"]}
    bad_tlds = {t.lower().lstrip(".") for t in ucfg["suspicious_tlds"]}
    protected = cfg["header"]["protected_domains"]

    findings: list[Finding] = []
    items, ip_hits = [], []
    flagged_hosts = set()
    for u in collect_urls(pe, extra):
        url, src = u["url"], u["source"]
        scheme, host, has_userinfo, port = _host_of(url)
        info = {"url": url[:300], "source": src, "host": host}
        items.append(info)
        tag = {"href": "連結", "form": "表單送出位址", "embed": "內嵌框架", "text": "內文網址",
               "qr": "QR Code 網址", "redirect": "跳轉參數中的網址"}[src]

        if scheme in ("javascript", "data", "vbscript"):
            findings.append(Finding(M, "SCRIPT_URL", 2.5, f"{tag}使用 {scheme}: 協定：{url[:80]}"))
            continue
        if not host:
            continue

        ip = parse_ip_host(host)
        if ip is not None:
            info["ip"] = str(ip)
            if ip_whitelisted(ip, nets):
                info["ip_whitelisted"] = True
            else:
                obf = "" if host.strip("[]") == str(ip) else f"（混淆寫法 {host} = {ip}）"
                ip_hits.append(str(ip))
                findings.append(Finding(M, "IP_URL", 5.0,
                                        f"{tag}直接使用 IP 位址 {ip}{obf}，且不在 IP 白名單 → 判定為惡意：{url[:100]}"))
            continue

        uni = idna_decode(host)
        od = org_domain(uni)
        if host in blocklist or od in blocklist or url.lower().rstrip("/") in blocklist:
            findings.append(Finding(M, "URL_BLOCKLIST", 10.0, f"{tag}命中本機網址黑名單：{uni}"))
        if has_userinfo:
            findings.append(Finding(M, "URL_USERINFO", 2.5, f"{tag}含帳密段（@ 前的內容是障眼法），實際前往 {uni}"))
        if host not in flagged_hosts:
            flagged_hosts.add(host)
            for f in domain_spoof_findings(host, protected, M, f"{tag}網域"):
                findings.append(f)
            if od in shorteners or host in shorteners:
                findings.append(Finding(M, "URL_SHORTENER", 1.0, f"{tag}使用短網址服務（隱藏真正目的地）：{host}"))
            tld = uni.rsplit(".", 1)[-1]
            if tld in bad_tlds:
                findings.append(Finding(M, "SUSPICIOUS_TLD", 0.8, f"{tag}使用高風險頂級網域 .{tld}：{uni}"))
        if port and port not in (80, 443):
            findings.append(Finding(M, "NONSTANDARD_PORT", 0.5, f"{tag}使用非標準埠 {port}：{uni}"))
        if scheme == "http" and _LOGIN_WORDS.search(url):
            findings.append(Finding(M, "HTTP_LOGIN", 0.5, f"{tag}未加密（http）卻像登入/驗證頁：{url[:80]}"))
        if src == "form":
            findings.append(Finding(M, "FORM_IN_EMAIL", 2.0, f"信件內嵌表單，資料會送到 {uni}（常見於竊取帳密）"))
        if src == "qr":
            findings.append(Finding(M, "QR_URL", 1.5, f"圖片中的 QR Code 指向 {uni}（QR Code 釣魚常用來躲避網址掃描）"))

        # 顯示文字是網域，但與實際目的地不同
        m = _DOMAINISH.match(u["text"] or "")
        if src == "href" and m:
            shown = idna_decode(m.group(1).lower())
            if "." in shown and org_domain(shown) != od:
                findings.append(Finding(M, "LINK_TEXT_MISMATCH", 2.5,
                                        f"連結文字顯示 {shown}，實際前往 {uni}"))

    # 同一規則多次命中時，只有前三次計分，避免分數爆量
    counted: dict[str, int] = {}
    for f in findings:
        counted[f.code] = counted.get(f.code, 0) + 1
        if counted[f.code] > 3:
            f.points = 0.0
    score = sum(f.points for f in findings)
    return {"score": round(score, 2), "count": len(items), "items": items[:50],
            "ip_url_hits": ip_hits, "findings": findings}
