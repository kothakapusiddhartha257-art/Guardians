"""Offline email threat signals adapted from the supplied threat_detection kit.

All checks are deterministic and inspect data already present in the message.
They never follow URLs, execute attachments, or submit credentials.
"""
from __future__ import annotations

from email import policy
from email.utils import parseaddr
from email.parser import BytesParser
from hashlib import sha256
from ipaddress import ip_address
import re
from urllib.parse import urlparse

from app.header_analysis.received_chain import parse_received_chain
from app.services.network_intelligence import inspect_sender_network

SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "info", "tk", "ml", "ga", "cf", "gq", "zip", "mov"}
DANGEROUS_EXTENSIONS = {"exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "msi", "dll", "hta", "lnk", "jar", "iso", "img"}
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
BRAND_DOMAINS = {"microsoft": {"microsoft.com", "office.com", "office365.com"},
                 "hdfc": {"hdfcbank.com", "hdfc.com"},
                 "google": {"google.com", "gmail.com"}, "paypal": {"paypal.com"},
                 "amazon": {"amazon.com"}, "apple": {"apple.com"}}


def _signal(rule: str, severity: str, points: int, description: str, mitre: str) -> dict:
    return {"rule": rule, "severity": severity, "points": points, "description": description, "mitre_attack_id": mitre}


def _body(message) -> str:
    chunks: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            chunks.append(part.get_content())
        except Exception:
            payload = part.get_payload(decode=True) or b""
            chunks.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(chunks)


def analyze_local_threats(raw: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    body = _body(message)
    text = f"{message.get('Subject', '')}\n{body}".lower()
    signals: list[dict] = []
    urls: list[dict] = []
    attachments: list[dict] = []
    _chain, sender_ip = parse_received_chain(message)
    ip_intelligence = inspect_sender_network(sender_ip)
    if ip_intelligence.get("status") == "available":
        ptr_check = ip_intelligence.get("forward_confirmed_reverse_dns", {})
        if ptr_check.get("matches") is False:
            signals.append(_signal("reverse_dns_mismatch", "medium", 10, "PTR hostname does not resolve back to the sender IP", "T1583"))
        if ip_intelligence.get("tor", {}).get("is_tor_exit_node"):
            signals.append(_signal("tor_exit_node", "high", 20, "Sender IP is listed as a Tor exit node", "T1090.003"))
        anonymity = ip_intelligence.get("anonymity", {})
        if anonymity.get("is_vpn") or anonymity.get("is_proxy"):
            signals.append(_signal("vpn_or_proxy_sender", "medium", 12,
                                   "Sender infrastructure is classified as a VPN or public proxy by configured intelligence", "T1090"))
        if ip_intelligence.get("infrastructure_risk", {}).get("is_known_high_risk"):
            signals.append(_signal("high_risk_sender_asn", "high", 20,
                                   "Sender IP belongs to a locally flagged high-risk hosting or anonymity ASN", "T1583"))

    # Catch brand tokens embedded in longer or homoglyph-normalized sender
    # domains, e.g. micros0ft-security.example and hdfc-secureverify.com.
    _name, from_address = parseaddr(message.get("From", "").replace("\\", ""))
    sender_domain = from_address.rsplit("@", 1)[-1].lower() if "@" in from_address else ""
    if not sender_domain:
        match = re.search(r"@([a-z0-9.-]+)", message.get("From", "").replace("\\", ""), re.IGNORECASE)
        sender_domain = match.group(1).lower() if match else ""
    normalized_domain = sender_domain.replace("0", "o").replace("1", "l").replace("3", "e")
    for brand, legitimate_domains in BRAND_DOMAINS.items():
        # A legitimate brand may use subdomains such as accounts.google.com.
        # Only flag a brand token when the domain is neither the approved
        # domain nor a subdomain of one of its approved domains.
        is_legitimate_brand_domain = any(
            sender_domain == domain or sender_domain.endswith(f".{domain}")
            for domain in legitimate_domains
        )
        if brand in normalized_domain and not is_legitimate_brand_domain:
            signals.append(_signal("brand_impersonation", "critical", 35,
                                   f"Sender domain '{sender_domain}' impersonates the protected brand '{brand}'",
                                   "T1566.002"))
            break

    for url in dict.fromkeys(URL_RE.findall(body)):
        parsed = urlparse(url)
        host = parsed.hostname or ""
        reasons: list[str] = []
        try:
            ip_address(host)
            reasons.append("URL uses a raw IP address instead of a domain")
        except ValueError:
            if host.rsplit(".", 1)[-1].lower() in SUSPICIOUS_TLDS:
                reasons.append("URL uses a frequently abused top-level domain")
        if parsed.scheme == "http" and any(word in host.lower() for word in ("bank", "login", "account", "secure")):
            reasons.append("Sensitive-looking destination uses unencrypted HTTP")
        if reasons:
            signals.append(_signal("suspicious_url", "high", 15, "; ".join(reasons), "T1566.002"))
        urls.append({"url": url, "anchor_text": url, "risk_reasons": reasons})

    urgency = bool(re.search(r"\b(urgent|immediately|action required|within \d+ hours?|only \d+ hours?|valid for \d+ hours?|suspend|final notice)\b", text))
    authority = bool(re.search(r"\b(ceo|cfo|director|executive|it support|security team|helpdesk)\b", text))
    financial = bool(re.search(r"\b(wire transfer|bank transfer|invoice|routing number|swift|iban|gift card|payment)\b", text))
    credentials = bool(re.search(r"\b(password|credentials|verify your account|log in|login|mfa)\b", text))
    if financial and (urgency or authority):
        signals.append(_signal("bec_financial_pressure", "critical", 30, "Financial request combined with urgency or authority pressure", "T1657"))
    direct_sensitive_request = bool(re.search(r"\b(otp|one.time password|debit card|card information|internet banking password|account number)\b", text))
    if credentials and (urgency or urls or direct_sensitive_request):
        points = 35 if direct_sensitive_request else 25
        signals.append(_signal("credential_harvesting", "critical" if direct_sensitive_request else "high", points,
                               "Request for credentials or banking secrets combined with coercive context", "T1056"))
    if re.search(r"\battachment:\s*[^\s]+\.(html?|js|exe|zip)\b", text):
        signals.append(_signal("suspicious_attachment_reference", "high", 15,
                               "Message references a potentially dangerous HTML, script, executable, or archive attachment", "T1204.002"))

    # Employment fraud / advance-fee scams: do not flag a normal job offer on
    # one weak cue; require the high-confidence combination of a waived
    # interview, an upfront fee, and a request for identity/financial records.
    no_interview = bool(re.search(r"\b(no interview|required interview is not|required because .*profile)\b", text))
    upfront_fee = bool(re.search(r"\b(refundable |registration |document[ -]verification |processing |joining )?fee\b", text))
    identity_documents = bool(re.search(r"\b(aadhaar|pan details|passport|address proof|bank account information)\b", text))
    if no_interview and upfront_fee and identity_documents:
        signals.append(_signal("employment_advance_fee_scam", "critical", 45,
                               "Employment offer waives an interview while demanding an upfront fee and sensitive identity or bank documents",
                               "T1566"))
    if no_interview and urgency and (upfront_fee or identity_documents):
        signals.append(_signal("employment_pressure_tactic", "high", 25,
                               "Employment message combines waived screening with a short deadline and financial or identity request",
                               "T1656"))

    delivery_claim = bool(re.search(r"\b(delivery failed|package|parcel|tracking number|redelivery|shipment)\b", text))
    delivery_payment = bool(re.search(r"\b(redelivery charge|delivery charge|payment information|pay.*fee)\b", text))
    address_request = bool(re.search(r"\b(update|confirm).{0,40}(address|delivery details)\b", text))
    if delivery_claim and urgency and (delivery_payment or address_request):
        signals.append(_signal("parcel_delivery_phishing", "critical", 40,
                               "Delivery failure claim combines a short deadline with address or payment collection", "T1566.002"))
    if delivery_claim and delivery_payment and address_request:
        signals.append(_signal("redelivery_fee_scam", "high", 30,
                               "Parcel message requests payment and address changes for a supposed redelivery", "T1656"))
    spam_words = re.findall(r"\b(lottery|winner|prize|bitcoin|viagra|cialis|free|cash)\b", text)
    if len(spam_words) >= 2:
        signals.append(_signal("spam_keyword_cluster", "medium", 12, "Multiple spam-associated keywords detected", "T1566"))

    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        data = part.get_payload(decode=True) or b""
        lower_name = filename.lower()
        extensions = lower_name.split(".")[1:]
        reasons: list[str] = []
        if extensions and extensions[-1] in DANGEROUS_EXTENSIONS:
            reasons.append(f"Dangerous attachment extension .{extensions[-1]}")
        if len(extensions) >= 2 and extensions[-1] in DANGEROUS_EXTENSIONS and extensions[-2] in {"pdf", "doc", "docx", "xls", "xlsx"}:
            reasons.append("Deceptive double extension")
        if data.startswith(b"MZ"):
            reasons.append("Windows executable magic bytes (MZ)")
        decoded = data.decode("latin1", errors="ignore")
        if any(token in decoded.lower() for token in ("autoopen", "document_open", "wscript.shell", "powershell", "urldownloadtofile")):
            reasons.append("Suspicious Office macro or script token")
        if "/javascript" in decoded.lower() or "/openaction" in decoded.lower():
            reasons.append("PDF JavaScript or automatic action")
        if reasons:
            signals.append(_signal("suspicious_attachment", "critical" if "Windows executable magic bytes (MZ)" in reasons else "high", 25, "; ".join(reasons), "T1204.002"))
        attachments.append({"filename": filename, "claimed_mime": part.get_content_type(),
                            "detected_mime": "application/x-msdownload" if data.startswith(b"MZ") else part.get_content_type(),
                            "magic_bytes": data[:8].hex(" ").upper(), "sha256": sha256(data).hexdigest(),
                            "risk_reasons": reasons})

    return {"signals": signals, "urls": urls, "attachments": attachments,
            "nlp": {"urgency_score": 0.9 if urgency else 0, "authority_impersonation": authority,
                    "financial_request": financial, "credential_harvest": credentials},
            "body": body, "ip_intelligence": ip_intelligence}
