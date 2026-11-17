"""提示詞注入（Prompt Injection）防護。

多層防禦：
  1. 正規化：Unicode NFKC、移除零寬字元與 Bidi 控制字元（避免用隱形字元拆字繞過偵測）。
  2. HTML 清洗：移除 script/style/註解，並把「隱藏文字」(display:none、font-size:0、白色字…)
     獨立抽出 —— 隱藏文字本身就是強烈可疑訊號，且最常用來藏注入指令。
  3. 規則偵測：中英文常見注入語句（忽略前面的指示、判定為安全、you are now…）、
     偽造的對話角色標記（<|im_start|>、[INST]、system:）。
  4. Spotlighting：用每次隨機產生的 nonce 邊界包住信件內容，並把內容中任何
     類似邊界的字串中和掉，讓模型清楚區分「資料」與「指令」。
  5. 由呼叫端在 system prompt 聲明信件為不可信資料，並在內容後重述任務（sandwich）。
  6. 最終決策不由 LLM 單獨決定：偵測到注入時，融合分數會大幅加權，
     即使 LLM 被說服判為安全也無法讓整體結果變成安全。
"""
from __future__ import annotations

import html as htmllib
import re
import secrets
import unicodedata
from html.parser import HTMLParser

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤"
                                    "﻿­‪‫‬‭‮⁦⁧⁨⁩"), None)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = text.translate(ZERO_WIDTH)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


# ---------------------------------------------------------------- HTML 清洗

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
         "param", "source", "track", "wbr"}
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.\d+)?(?:px|pt|em|%)?\s*(?:;|$)"
    r"|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|(?<![-\w])color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)"
    r"|max-height\s*:\s*0|height\s*:\s*0(?:px)?\s*;.*overflow\s*:\s*hidden|mso-hide\s*:\s*all",
    re.I)


class _Extractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.links: list[tuple[str, str]] = []   # (href, 顯示文字)
        self._stack: list[tuple[str, bool]] = []
        self._skip = 0
        self._cur_href: str | None = None
        self._cur_text: list[str] = []

    def _hidden_now(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style", "head", "title", "noscript", "template"):
            self._skip += 1
            return
        hidden = "hidden" in a or a.get("aria-hidden") == "true" or bool(_HIDDEN_STYLE.search(a.get("style", "")))
        if tag in ("br", "p", "div", "tr", "li"):
            (self.hidden if self._hidden_now() else self.visible).append("\n")
        if tag == "a":
            self._cur_href, self._cur_text = a.get("href", ""), []
        if tag not in _VOID:
            self._stack.append((tag, hidden))

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title", "noscript", "template"):
            self._skip = max(0, self._skip - 1)
            return
        if tag == "a" and self._cur_href is not None:
            self.links.append((self._cur_href, "".join(self._cur_text).strip()))
            self._cur_href = None
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data):
        if self._skip:
            return
        (self.hidden if self._hidden_now() else self.visible).append(data)
        if self._cur_href is not None:
            self._cur_text.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.hidden.append(f" [HTML註解] {data} ")


def html_to_text(html: str) -> tuple[str, str, list[tuple[str, str]]]:
    """回傳 (可見文字, 隱藏文字, 連結清單)。"""
    p = _Extractor()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        return normalize(re.sub(r"<[^>]+>", " ", htmllib.unescape(html or ""))), "", []
    return normalize("".join(p.visible)), normalize("".join(p.hidden)), p.links


# ---------------------------------------------------------------- 注入偵測

_PATTERNS = [
    # 英文
    (r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|all|any|preceding|system)\b.{0,30}"
     r"\b(instructions?|prompts?|rules?|directions?|context|guidelines?)\b", "要求忽略先前指示"),
    (r"\b(classify|mark|label|flag|treat|consider|rate|judge)\b.{0,40}\b(this|the)\s+(e-?mail|message)\b.{0,30}"
     r"\b(as\s+)?(safe|legit(imate)?|benign|harmless|not\s+(a\s+)?(phishing|spam|scam))\b", "要求判定為安全"),
    (r"\b(this|the)\s+(e-?mail|message)\s+is\s+(safe|legit(imate)?|benign|not\s+(a\s+)?(phishing|scam|spam))\b", "自稱為安全信件"),
    (r"\byou\s+are\s+now\b|\bact\s+as\b|\bnew\s+(role|instructions?)\b|\bdeveloper\s+mode\b|\bjailbreak\b", "角色扮演/越獄"),
    (r"\b(system|assistant)\s*(prompt|message|:)", "偽造系統/助理訊息"),
    (r"\b(output|respond|reply|answer)\s+(only\s+)?(with\s+)?[\"']?(B|safe|0|false)[\"']?\b", "指定模型輸出"),
    # 中文（正規化後繁簡都涵蓋）
    (r"(忽略|忽視|無視|无视|不要理會|不要理会|跳過|跳过|覆蓋|覆盖).{0,12}(前面|之前|先前|以上|上述|上面|所有|全部|原本|原先|系統|系统).{0,8}"
     r"(指示|指令|提示|規則|规则|設定|设定|要求|prompt)", "要求忽略先前指示"),
    (r"(判定|判斷|判断|認定|认定|視為|视为|標記|标记|歸類|归类|分類|分类|回答|輸出|输出|評為|评为).{0,15}"
     r"(安全|正常|合法|無害|无害|非詐騙|非诈骗|不是詐騙|不是诈骗|非釣魚|非钓鱼|不是釣魚|不是钓鱼|白名單|白名单)", "要求判定為安全"),
    (r"(這|这|此|本)(封)?(信|郵件|邮件|訊息|讯息).{0,6}(是|為|为)?(安全|正常|合法).{0,4}(的|信件|郵件|邮件)", "自稱為安全信件"),
    (r"(你現在是|你现在是|你是一個|你是一个|扮演|角色設定|角色设定|開發者模式|开发者模式|越獄|越狱)", "角色扮演/越獄"),
    (r"(系統提示|系统提示|系統指令|系统指令|系統訊息|系统讯息|管理員指令|管理员指令)", "偽造系統/助理訊息"),
    # 對話格式 token
    (r"<\|?(im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?INST\]|<<SYS>>|###\s*(instruction|system)",
     "偽造對話格式標記"),
]
_COMPILED = [(re.compile(p, re.I | re.S), label) for p, label in _PATTERNS]


def detect_injection(text: str) -> list[dict]:
    text = normalize(text)
    hits = []
    for rx, label in _COMPILED:
        for m in rx.finditer(text):
            hits.append({"type": label, "match": m.group(0)[:120]})
            break
    return hits


# ---------------------------------------------------------------- Spotlighting

def new_nonce() -> str:
    return secrets.token_hex(6)


def spotlight(content: str, max_chars: int, nonce: str | None = None) -> tuple[str, str]:
    """用隨機 nonce 邊界包住不可信內容；回傳 (包裝後內容, nonce)。"""
    nonce = nonce or new_nonce()
    content = content[:max_chars]
    # 中和內容中可能偽造的邊界或對話標記
    content = re.sub(r"<{2,}|>{2,}", "‹‹", content)
    content = re.sub(r"(?i)</?\s*(email|untrusted|data|system|user|assistant)[^>]*>", "[tag-removed]", content)
    content = re.sub(r"<\|[^|>]{1,30}\|>", "[token-removed]", content)
    wrapped = f"<<<UNTRUSTED_EMAIL_{nonce}>>>\n{content}\n<<<END_UNTRUSTED_EMAIL_{nonce}>>>"
    return wrapped, nonce
