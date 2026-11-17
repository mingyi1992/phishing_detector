"""信件解析：讀取 .eml，拆出標頭、純文字、HTML 與附件。"""
from __future__ import annotations

import email
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from pathlib import Path


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes


@dataclass
class ParsedEmail:
    msg: EmailMessage
    raw: bytes
    subject: str
    text: str
    html: str
    attachments: list[Attachment] = field(default_factory=list)


def _decode_part(part) -> str:
    try:
        return part.get_content()
    except Exception:  # 未知 charset 或編碼錯誤時退回寬鬆解碼
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=policy.default)
    texts, htmls, atts = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        ctype = part.get_content_type()
        if filename or disposition == "attachment":
            data = part.get_payload(decode=True) or b""
            atts.append(Attachment(filename or "unnamed", ctype, data))
        elif ctype == "text/plain":
            texts.append(_decode_part(part))
        elif ctype == "text/html":
            htmls.append(_decode_part(part))
    return ParsedEmail(
        msg=msg,
        raw=raw,
        subject=str(msg.get("Subject", "")),
        text="\n".join(texts),
        html="\n".join(htmls),
        attachments=atts,
    )


def load_eml(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
