import hashlib
import uuid
import re
import email
from email import policy
from email.header import decode_header
from email.utils import parseaddr
from typing import List, Tuple, Dict, Any, Optional
from bs4 import BeautifulSoup

from backend.app.schemas.canonical import (
    ParsedEmail, HeaderNormalized, EmailAddressRecord, MessageIdRecord,
    UrlRecord, AttachmentRecord
)


def decode_rfc2047(header_val: Optional[str]) -> str:
    if not header_val:
        return ""
    try:
        decoded_fragments = decode_header(header_val)
        res = []
        for fragment, encoding in decoded_fragments:
            if isinstance(fragment, bytes):
                if encoding:
                    try:
                        res.append(fragment.decode(encoding, errors="replace"))
                    except Exception:
                        res.append(fragment.decode("utf-8", errors="replace"))
                else:
                    res.append(fragment.decode("utf-8", errors="replace"))
            else:
                res.append(str(fragment))
        return " ".join(res).strip()
    except Exception:
        return str(header_val).strip()


def parse_address_field(raw_field: Optional[str]) -> Optional[EmailAddressRecord]:
    if not raw_field:
        return None
    decoded = decode_rfc2047(raw_field)
    name, addr = parseaddr(decoded)
    if not addr and "@" in decoded:
        # Fallback regex extraction if parseaddr misses edge case
        match = re.search(r'[\w\.-]+@[\w\.-]+', decoded)
        if match:
            addr = match.group(0)
    
    if not addr:
        return None

    domain = addr.split("@")[-1].lower().strip() if "@" in addr else ""
    return EmailAddressRecord(
        display_name=name.strip() if name else None,
        address=addr.lower().strip(),
        domain=domain
    )


def extract_urls_from_text(text: str) -> List[str]:
    url_pattern = r'https?://[^\s<>"\')]+|www\.[^\s<>"\')]+'
    return re.findall(url_pattern, text)


def sanitize_html(raw_html: str) -> Tuple[str, List[UrlRecord]]:
    if not raw_html:
        return "", []
    try:
        soup = BeautifulSoup(raw_html, "html.parser")
        # Remove dangerous active elements
        for tag in soup(["script", "iframe", "object", "embed", "applet", "style"]):
            tag.decompose()

        urls: List[UrlRecord] = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            displayed = a.get_text().strip() or href
            if href.startswith("http://") or href.startswith("https://") or href.startswith("//"):
                urls.append(UrlRecord(displayed=displayed, actual_href=href))

        # Return clean HTML string and extracted URLs
        return str(soup), urls
    except Exception:
        return raw_html, []


def parse_email_bytes(raw_bytes: bytes, email_id: Optional[str] = None) -> ParsedEmail:
    if not email_id:
        email_id = str(uuid.uuid4())

    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_size_bytes = len(raw_bytes)

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    # Extract raw and normalized headers
    headers_raw: Dict[str, Any] = {}
    for k, v in msg.items():
        headers_raw.setdefault(k, []).append(str(v))

    received_chain_raw = [str(r) for r in msg.get_all("Received", [])]

    from_rec = parse_address_field(msg.get("From"))
    reply_to_rec = parse_address_field(msg.get("Reply-To"))
    return_path_rec = parse_address_field(msg.get("Return-Path"))
    
    msg_id_raw = msg.get("Message-ID", "").strip()
    msg_id_domain = None
    if "@" in msg_id_raw:
        msg_id_domain = msg_id_raw.split("@")[-1].rstrip(">").strip().lower()

    message_id_rec = MessageIdRecord(raw=msg_id_raw, domain=msg_id_domain) if msg_id_raw else None

    date_str = msg.get("Date")
    subject_str = decode_rfc2047(msg.get("Subject", ""))

    headers_normalized = HeaderNormalized(
        from_address=from_rec,
        reply_to=reply_to_rec,
        return_path=return_path_rec,
        message_id=message_id_rec,
        date=date_str,
        subject=subject_str
    )

    mime_structure: List[str] = []
    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[AttachmentRecord] = []
    extracted_urls: List[UrlRecord] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            mime_structure.append(content_type)

            filename = part.get_filename()
            if filename:
                filename = decode_rfc2047(filename)

            # Check if it's an attachment
            if "attachment" in content_disposition.lower() or filename:
                payload = part.get_payload(decode=True) or b""
                att_sha256 = hashlib.sha256(payload).hexdigest()
                attachments.append(AttachmentRecord(
                    filename=filename or "unnamed_attachment",
                    mime=content_type,
                    size=len(payload),
                    sha256=att_sha256
                ))
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_text_parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        body_text_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_html_parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        body_html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type()
        mime_structure.append(content_type)
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded_text = payload.decode(charset, errors="replace")
            if content_type == "text/html":
                body_html_parts.append(decoded_text)
            else:
                body_text_parts.append(decoded_text)

    raw_body_text = "\n".join(body_text_parts).strip()
    raw_body_html = "\n".join(body_html_parts).strip()

    # Sanitize HTML and extract URLs
    sanitized_html, html_urls = sanitize_html(raw_body_html)
    extracted_urls.extend(html_urls)

    # Extract plaintext URLs
    text_urls = extract_urls_from_text(raw_body_text)
    for u in text_urls:
        if not any(x.actual_href == u for x in extracted_urls):
            extracted_urls.append(UrlRecord(displayed=u, actual_href=u))

    # If body_text is empty but HTML exists, extract plain text from soup
    if not raw_body_text and sanitized_html:
        try:
            soup = BeautifulSoup(sanitized_html, "html.parser")
            raw_body_text = soup.get_text(separator=" ").strip()
        except Exception:
            pass

    return ParsedEmail(
        email_id=email_id,
        sha256=sha256,
        raw_size_bytes=raw_size_bytes,
        mime_structure=mime_structure,
        headers_raw=headers_raw,
        headers_normalized=headers_normalized,
        received_chain_raw=received_chain_raw,
        body_text=raw_body_text,
        body_html=sanitized_html,
        urls=extracted_urls,
        attachments=attachments
    )
