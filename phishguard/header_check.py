"""(1) 信件標頭檢查：SPF / DKIM / DMARC、From / Reply-To / Return-Path 一致性、Received 路徑。

信任邊界（Trust boundary）：
  * Received 由上往下讀，第一個「by 我方收信伺服器（MX_HOSTNAMES）」的跳點就是邊界，
    該跳點記錄的對方 IP 才是真正的來源 IP；邊界以下的 Received 全部可由寄件者偽造，只當參考。
  * Authentication-Results / Received-SPF 只採信「位於邊界之上」（由我方伺服器加入）的標頭；
    若有設定 TRUSTED_AUTHSERV_IDS，authserv-id 還必須在清單內。
  * 邊界以下若有聲稱 pass 的驗證結果、而我方結果為 fail → 判定為偽造驗證結果。
  * 未設定 MX_HOSTNAMES / TRUSTED_AUTHSERV_IDS 時退回啟發式判斷並在報告中警告。
ARC：郵件論壇/轉寄會讓 DMARC 合法地失敗；若我方驗證結果 arc=pass 且 ARC 簽章者在
ARC_TRUSTED_SEALERS 內，DMARC fail 的扣分會大幅降低。
"""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from email.utils import getaddresses, parsedate_to_datetime

from .common import (Finding, domain_of, idna_decode, levenshtein, org_domain, scripts_of,
                     skeleton)
from .parser import ParsedEmail

M = "header"

_SPF_PTS = {"pass": -0.5, "fail": 2.0, "softfail": 1.0, "neutral": 0.5, "none": 0.5,
            "permerror": 0.5, "temperror": 0.3}
_DKIM_PTS = {"pass": -0.5, "fail": 2.0, "neutral": 0.5, "none": 0.5, "policy": 0.5,
             "permerror": 0.5, "temperror": 0.3}
_DMARC_PTS = {"pass": -1.0, "fail": 3.0, "none": 1.0, "permerror": 0.5, "temperror": 0.3,
              "bestguesspass": -0.3}

_SERVICE_WORDS = re.compile(
    r"客服|服務|服务|通知|中心|帳戶|帐户|帳號|帐号|安全|團隊|团队|系統|系统|官方|"
    r"\b(support|service|services|team|security|account|billing|notification|notice|alert|"
    r"helpdesk|admin|customer|official|no-?reply)\b", re.I)


# ---------------------------------------------------------------- Received 解析

_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")


def _parse_received(h: str) -> dict:
    h = " ".join(str(h).split())
    body, _, date_s = h.rpartition(";")
    if not body:
        body, date_s = h, ""
    hop = {"from": None, "rdns": None, "ip": None, "by": None, "time": None}
    m = re.search(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", body, re.I)
    if m:
        hop["from"] = m.group(1)
        r = re.match(r"\s*([\w.-]+)", m.group(2) or "")
        if r and not re.fullmatch(r"[\d.]+", r.group(1)):
            hop["rdns"] = r.group(1)
    m = re.search(r"\bby\s+(\S+)", body, re.I)
    if m:
        hop["by"] = m.group(1).lower().rstrip(";")
    ipm = _IP_RE.search(re.split(r"\sby\s", body, maxsplit=1, flags=re.I)[0])
    if ipm:
        hop["ip"] = ipm.group(1)
    try:
        hop["time"] = parsedate_to_datetime(date_s.strip()) if date_s.strip() else None
    except Exception:
        hop["time"] = None
    return hop


def _is_public(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global if ip else False
    except ValueError:
        return False


def _host_match(host: str | None, names: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == n.lower() or host.endswith("." + n.lower()) for n in names)


def locate_boundary(pe: ParsedEmail, cfg: dict) -> dict:
    """找出信任邊界：回傳 {hops(由上到下), boundary(索引或 None), header_index, method}。"""
    items = list(pe.msg.items())
    rec_pos = [i for i, (k, _) in enumerate(items) if k.lower() == "received"]
    hops = [_parse_received(items[i][1]) for i in rec_pos]
    mx = cfg["header"]["mx_hostnames"]
    boundary, method = None, None
    if mx:
        for i, h in enumerate(hops):
            if _host_match(h["by"], mx) and not _host_match(h["from"], mx):
                boundary, method = i, "MX_HOSTNAMES"
                break
    if boundary is None:  # 啟發式：由上往下第一個來自公網 IP 的跳點
        for i, h in enumerate(hops):
            if _is_public(h["ip"]):
                boundary, method = i, "heuristic"
                break
    header_index = rec_pos[boundary] if boundary is not None else (rec_pos[0] if rec_pos else len(items))
    return {"items": items, "hops": hops, "boundary": boundary, "header_index": header_index,
            "method": method}


# ---------------------------------------------------------------- 驗證結果

def _parse_ar(h: str) -> dict:
    h = " ".join(h.split())
    authserv = h.split(";", 1)[0].strip().split()[0].lower() if h.strip() else ""
    res = {"authserv": authserv, "spf": None, "dkim": [], "dmarc": None, "arc": None,
           "spf_mailfrom": None}
    m = re.search(r"\bspf=(\w+)", h, re.I)
    if m:
        res["spf"] = m.group(1).lower()
        mf = re.search(r"smtp\.mailfrom=([^\s;]+)", h, re.I)
        res["spf_mailfrom"] = mf.group(1) if mf else None
    for dm in re.finditer(r"\bdkim=(\w+)([^;]*)", h, re.I):
        d = re.search(r"header\.(?:d|i)=@?([^\s;]+)", dm.group(2), re.I)
        res["dkim"].append((dm.group(1).lower(), d.group(1).lower() if d else ""))
    m = re.search(r"\bdmarc=(\w+)", h, re.I)
    res["dmarc"] = m.group(1).lower() if m else None
    m = re.search(r"\barc=(\w+)", h, re.I)
    res["arc"] = m.group(1).lower() if m else None
    return res


def check_auth(pe: ParsedEmail, cfg: dict, bnd: dict, findings: list[Finding], synthetic: bool) -> dict:
    hcfg = cfg["header"]
    items, cut = bnd["items"], bnd["header_index"]
    trusted_ids = {t.lower() for t in hcfg["trusted_authserv_ids"]}

    trusted, untrusted = [], []
    for i, (k, v) in enumerate(items):
        if k.lower() != "authentication-results":
            continue
        ar = _parse_ar(str(v))
        ok = i < cut and (not trusted_ids or ar["authserv"] in trusted_ids)
        (trusted if ok else untrusted).append(ar)

    auth = {"spf": None, "dkim": [], "dmarc": None, "arc": None, "spf_mailfrom": None,
            "source": None, "trusted": bool(trusted)}
    if trusted:
        top = trusted[0]
        auth.update({k: top[k] for k in ("spf", "dkim", "dmarc", "arc", "spf_mailfrom")})
        auth["source"] = top["authserv"]
    else:
        # 退而求其次：邊界之上的 Received-SPF
        for i, (k, v) in enumerate(items):
            if k.lower() == "received-spf" and i < cut:
                auth["spf"] = str(v).split()[0].lower()
                auth["source"] = "Received-SPF"
                break

    if synthetic:
        return auth
    if not trusted and auth["spf"] is None:
        msg = ("沒有我方伺服器產生的驗證結果（Authentication-Results / Received-SPF），無法確認 SPF/DKIM/DMARC"
               if not untrusted else
               f"驗證結果皆不在信任邊界內或不是信任的伺服器產生（{', '.join(a['authserv'] for a in untrusted)}），已忽略")
        findings.append(Finding(M, "AUTH_RESULTS_UNTRUSTED" if untrusted else "AUTH_RESULTS_MISSING", 1.0, msg))

    # 邊界外聲稱 pass、我方結果卻 fail/none → 偽造
    if untrusted and trusted:
        fake = [a["authserv"] for a in untrusted
                if (a["dmarc"] == "pass" and auth["dmarc"] in ("fail", "none", None))
                or (a["spf"] == "pass" and auth["spf"] in ("fail", "softfail"))]
        if fake:
            findings.append(Finding(M, "FORGED_AUTH_RESULTS", 2.5,
                                    f"信件夾帶寄件端自稱 pass 的驗證結果（{', '.join(fake)}），與我方驗證結果矛盾，疑似偽造"))

    # ARC：轉寄 / 郵件論壇
    arc_ok = False
    if auth["arc"] == "pass":
        sealers = {org_domain(d) for d in hcfg["arc_trusted_sealers"]}
        seal_d = None
        for k, v in items:
            if k.lower() == "arc-seal":
                m = re.search(r"\bi=1\b", str(v)) and re.search(r"\bd=([^\s;]+)", str(v))
                if m:
                    seal_d = m.group(1).lower()
                    break
        arc_ok = bool(seal_d and org_domain(seal_d) in sealers)
        auth["arc_sealer"] = seal_d
    is_list = bool(pe.msg.get("List-Id"))

    for name, val, table in (("SPF", auth["spf"], _SPF_PTS), ("DMARC", auth["dmarc"], _DMARC_PTS)):
        if not val:
            continue
        pts, note = table.get(val, 0.5), ""
        if name == "DMARC" and val == "fail":
            if arc_ok:
                pts, note = 0.5, f"（ARC 驗證通過，簽章者 {auth.get('arc_sealer')}，屬轉寄/郵件論壇，已降低扣分）"
            elif is_list:
                pts, note = 1.5, "（含 List-Id，可能是郵件論壇轉寄，已降低扣分）"
        findings.append(Finding(M, f"{name}_{val.upper()}", pts, f"{name} 驗證結果：{val}{note}"))

    if auth["dkim"]:
        results = [r for r, _ in auth["dkim"]]
        best = "pass" if "pass" in results else results[0]
        findings.append(Finding(M, f"DKIM_{best.upper()}", _DKIM_PTS.get(best, 0.5),
                                f"DKIM 驗證結果：{', '.join(results)}"))
    elif trusted:
        findings.append(Finding(M, "DKIM_NONE", 0.5, "沒有 DKIM 簽章"))
    return auth


# ---------------------------------------------------------------- 仿冒網域

def lookalike(host: str, protected: list[str]) -> tuple[str, str] | None:
    """判斷網域是否仿冒受保護網域；回傳 (被仿冒的網域, 手法) 或 None。"""
    uni = idna_decode(host)
    od = org_domain(uni)
    prot_orgs = {org_domain(p) for p in protected}
    if od in prot_orgs:
        return None
    label = od.split(".")[0]
    for p in sorted(prot_orgs):
        plabel = p.split(".")[0]
        if len(plabel) < 4:
            continue
        if label != plabel and skeleton(label) == skeleton(plabel):
            return p, "同形字/字元替換"
        if 0 < levenshtein(skeleton(label), skeleton(plabel)) <= (1 if len(plabel) < 6 else 2):
            return p, "拼字近似"
        host_labels = uni.lower().split(".")
        if plabel in host_labels[:-2] or (len(plabel) >= 5 and plabel in label):
            return p, "品牌名稱嵌入網域"
    return None


def domain_spoof_findings(host: str, protected: list[str], module: str, what: str) -> list[Finding]:
    out = []
    uni = idna_decode(host)
    if "xn--" in host.lower():
        out.append(Finding(module, "PUNYCODE_DOMAIN", 2.0, f"{what} 使用 Punycode：{host}（顯示為 {uni}）"))
    scripts = scripts_of(uni.replace(".", ""))
    if len(scripts) > 1:
        out.append(Finding(module, "MIXED_SCRIPT_DOMAIN", 2.5,
                           f"{what} 混用多種文字系統（{'/'.join(sorted(scripts))}）：{uni}"))
    hit = lookalike(host, protected)
    if hit:
        pts = 3.5 if hit[1] == "同形字/字元替換" else 3.0
        out.append(Finding(module, "LOOKALIKE_DOMAIN", pts, f"{what} {uni} 疑似仿冒 {hit[0]}（{hit[1]}）"))
    return out


# ---------------------------------------------------------------- 寄件者一致性

def _brand_hit(display: str, brands: dict[str, list[str]], from_org: str) -> str | None:
    low = display.lower()
    for kw, domains in brands.items():
        k = kw.lower()
        if re.fullmatch(r"[\w .-]+", k):
            if not re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", low):
                continue
        elif k not in low:
            continue
        if from_org in {org_domain(d) for d in domains}:
            continue
        # 只有「名稱幾乎就是品牌」或「品牌 + 客服/通知等官方字眼」才算冒用，避免「apple 蘋果派」誤判
        rest = re.sub(re.escape(k), "", low, flags=re.I).strip(" -_|()[]")
        if len(rest) <= 3 or _SERVICE_WORDS.search(display):
            return kw
    return None


def check_identity(pe: ParsedEmail, cfg: dict, auth: dict, findings: list[Finding],
                   synthetic: bool = False) -> dict:
    hcfg = cfg["header"]
    msg = pe.msg
    from_raw = [str(h) for h in msg.get_all("From", [])]
    froms = getaddresses(from_raw)
    if len(froms) != 1 and not (synthetic and not from_raw):  # 資料集部分來源本來就沒有寄件者欄位
        findings.append(Finding(M, "FROM_COUNT", 2.0, f"From 欄位數量異常（{len(froms)} 個位址）"))
    disp_name, from_addr = froms[0] if froms else ("", "")
    from_dom = domain_of(from_addr)
    from_org = org_domain(from_dom)

    reply_to = getaddresses([str(h) for h in msg.get_all("Reply-To", [])])
    return_path = str(msg.get("Return-Path", "") or auth.get("spf_mailfrom") or "")
    rp_dom = domain_of(return_path)
    info = {"from": from_addr, "display_name": disp_name, "reply_to": [a for _, a in reply_to],
            "return_path": return_path}

    freemail = set(hcfg["freemail_domains"])
    for _, rt in reply_to:
        rt_dom = domain_of(rt)
        if rt_dom and org_domain(rt_dom) != from_org:
            pts = 2.0 + (1.0 if rt_dom in freemail and from_dom not in freemail else 0.0)
            findings.append(Finding(M, "REPLYTO_MISMATCH", pts,
                                    f"Reply-To ({rt}) 與 From ({from_addr}) 網域不一致"))

    dkim_aligned = any(r == "pass" and org_domain(d) == from_org for r, d in auth.get("dkim", []))
    if rp_dom and org_domain(rp_dom) != from_org:
        findings.append(Finding(M, "RETURNPATH_MISMATCH", 0.4 if dkim_aligned else 1.2,
                                f"Return-Path ({return_path}) 與 From ({from_addr}) 網域不一致"))
    if auth.get("dkim") and not dkim_aligned and any(r == "pass" for r, _ in auth["dkim"]):
        findings.append(Finding(M, "DKIM_NOT_ALIGNED", 0.8, "DKIM 通過，但簽章網域 (d=) 與 From 不對齊"))

    if disp_name:
        emb = domain_of(disp_name)
        if emb and org_domain(emb) != from_org:
            findings.append(Finding(M, "DISPLAYNAME_SPOOF", 2.0, f"顯示名稱內含其他網域的 email（{disp_name}）"))
        kw = _brand_hit(disp_name, hcfg["brands"], from_org)
        if kw:
            findings.append(Finding(M, "BRAND_IN_DISPLAYNAME", 1.5,
                                    f"顯示名稱以「{kw}」名義寄出，但寄件網域 {from_dom} 不是該品牌官方網域"))

    if from_dom:
        findings.extend(domain_spoof_findings(from_dom, hcfg["protected_domains"], M, "寄件網域"))
    return info


# ---------------------------------------------------------------- Received 路徑

def check_received(pe: ParsedEmail, bnd: dict, findings: list[Finding], synthetic: bool = False) -> list[dict]:
    hops, b = bnd["hops"], bnd["boundary"]
    if not hops:
        if not synthetic:
            findings.append(Finding(M, "NO_RECEIVED", 1.5, "沒有任何 Received 標頭（外部郵件不應如此）"))
        return []
    if len(hops) > 12:
        findings.append(Finding(M, "TOO_MANY_HOPS", 1.0, f"Received 轉送次數過多（{len(hops)}）"))

    chrono = list(reversed(hops))
    times = [h["time"] for h in chrono if h["time"]]
    for x, y in zip(times, times[1:]):
        try:
            if y < x - timedelta(minutes=5):
                findings.append(Finding(M, "RECEIVED_TIME_REVERSED", 1.5,
                                        f"Received 時間戳記倒序（{x.isoformat()} → {y.isoformat()}），可能有偽造的轉送紀錄"))
                break
        except TypeError:
            continue
    if len(times) >= 2:
        try:
            if times[-1] - times[0] > timedelta(days=2):
                findings.append(Finding(M, "RECEIVED_LONG_DELAY", 0.5, f"傳遞耗時異常長（{times[-1] - times[0]}）"))
        except TypeError:
            pass
    try:
        date_hdr = parsedate_to_datetime(str(pe.msg.get("Date"))) if pe.msg.get("Date") else None
        if date_hdr and times:
            if date_hdr - times[-1] > timedelta(hours=1):
                findings.append(Finding(M, "DATE_IN_FUTURE", 1.0, "Date 標頭晚於最後一次 Received（時間被竄改）"))
            elif times[0] - date_hdr > timedelta(days=3):
                findings.append(Finding(M, "DATE_TOO_OLD", 0.5, "Date 標頭比第一次 Received 早超過 3 天"))
    except Exception:
        pass

    if b is None:
        findings.append(Finding(M, "NO_TRUST_BOUNDARY", 0.5,
                                "找不到我方收信伺服器的 Received（請設定 MX_HOSTNAMES），無法確認真實來源 IP"))
    else:
        origin = hops[b]
        helo, rdns = origin["from"] or "", origin["rdns"] or ""
        if not _is_public(origin["ip"]) and bnd["method"] == "MX_HOSTNAMES":
            pass  # 內部轉寄
        elif rdns.lower() == "unknown" or (not rdns and helo):
            findings.append(Finding(M, "ORIGIN_NO_RDNS", 0.5,
                                    f"真實來源 IP {origin['ip']} 無反解（rDNS），HELO={helo}"))
        elif helo and rdns and not re.fullmatch(r"\[?[\d.]+\]?", helo) and org_domain(helo) != org_domain(rdns):
            findings.append(Finding(M, "HELO_RDNS_MISMATCH", 0.5, f"來源 HELO ({helo}) 與反解 ({rdns}) 不一致"))

    out = []
    for i, h in enumerate(hops):
        d = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in h.items()}
        d["trust"] = ("boundary" if i == b else "trusted" if b is not None and i < b else "untrusted")
        out.append(d)
    return list(reversed(out))


# ---------------------------------------------------------------- 入口

def analyze_headers(pe: ParsedEmail, cfg: dict, synthetic: bool = False) -> dict:
    findings: list[Finding] = []
    bnd = locate_boundary(pe, cfg)
    auth = check_auth(pe, cfg, bnd, findings, synthetic)
    ident = check_identity(pe, cfg, auth, findings, synthetic)
    path = check_received(pe, bnd, findings, synthetic)
    warnings = []
    if not synthetic:
        if not cfg["header"]["mx_hostnames"]:
            warnings.append("未設定 MX_HOSTNAMES：信任邊界以啟發式判斷，Received 偽造較難識破")
        if not cfg["header"]["trusted_authserv_ids"]:
            warnings.append("未設定 TRUSTED_AUTHSERV_IDS：只要位於邊界之上的驗證結果都會採信")
    origin = bnd["hops"][bnd["boundary"]] if bnd["boundary"] is not None else None
    score = max(0.0, sum(f.points for f in findings))
    return {
        "score": round(score, 2),
        "auth": {"spf": auth["spf"], "dkim": [r for r, _ in auth["dkim"]], "dmarc": auth["dmarc"],
                 "arc": auth["arc"], "source": auth["source"]},
        "identity": ident,
        "trust_boundary": {"method": bnd["method"], "origin_ip": origin["ip"] if origin else None,
                           "origin_helo": origin["from"] if origin else None},
        "received_path": path,
        "config_warnings": warnings,
        "findings": findings,
    }
