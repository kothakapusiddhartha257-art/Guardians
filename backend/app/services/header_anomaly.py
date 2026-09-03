import re
import unicodedata
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional
from backend.app.core.config import settings
from backend.app.schemas.canonical import ParsedEmail, HeaderAnomalyRuleResult

LEGITIMATE_ESPS = [
    "sendgrid.net", "sendgrid.com", "mailchimp.com", "mcsv.net", "mcdlv.net",
    "amazonses.com", "postmarkapp.com", "sparkpostmail.com", "mailgun.org",
    "mailgun.net", "exacttarget.com", "createsend.com", "hubspotemail.net",
    "constantcontact.com", "google.com", "googlemail.com", "outlook.com"
]

EXECUTIVE_VIP_PATTERNS = [
    r"\bceo\b", r"\bcfo\b", r"\bcoo\b", r"\bcto\b", r"\bpresident\b",
    r"\bdirector\b", r"\bexecutive\b", r"\bpayroll\b", r"\bhuman resources\b",
    r"\bhr department\b", r"\bit support\b", r"\bit helpdesk\b", r"\bbilling\b",
    r"\bfinance\b", r"\baccountant\b", r"\bvendor payments\b", r"\bsecurity team\b"
]


def has_unicode_confusables(text: str) -> bool:
    if not text:
        return False
    # Check if text contains non-ASCII characters that resemble Latin letters (e.g. Cyrillic, Greek)
    for char in text:
        cat = unicodedata.category(char)
        if ord(char) > 127:
            # Check script
            name = unicodedata.name(char, "")
            if any(s in name for s in ["CYRILLIC", "GREEK", "HEBREW", "ARABIC", "FULLWIDTH"]):
                return True
    return False


def detect_header_anomalies(parsed: ParsedEmail) -> List[HeaderAnomalyRuleResult]:
    results: List[HeaderAnomalyRuleResult] = []
    
    headers = parsed.headers_raw
    from_rec = parsed.headers_normalized.from_address
    reply_to_rec = parsed.headers_normalized.reply_to
    return_path_rec = parsed.headers_normalized.return_path
    msg_id_rec = parsed.headers_normalized.message_id
    date_str = parsed.headers_normalized.date

    from_domain = from_rec.domain if from_rec else ""
    from_name = from_rec.display_name if from_rec else ""

    # HDR-01: From address domain != Reply-To domain
    if reply_to_rec and from_domain:
        reply_domain = reply_to_rec.domain
        if reply_domain and reply_domain != from_domain:
            results.append(HeaderAnomalyRuleResult(
                rule_id="HDR-01",
                rule_name="Reply-To Domain Mismatch",
                triggered=True,
                evidence=f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}' ({reply_to_rec.address})",
                weight="High",
                score_impact=0.18
            ))
        else:
            results.append(HeaderAnomalyRuleResult(
                rule_id="HDR-01",
                rule_name="Reply-To Domain Mismatch",
                triggered=False,
                evidence="Reply-To domain matches From domain or is not set",
                weight="High",
                score_impact=0.0
            ))
    else:
        results.append(HeaderAnomalyRuleResult(
            rule_id="HDR-01",
            rule_name="Reply-To Domain Mismatch",
            triggered=False,
            evidence="No distinct Reply-To header specified",
            weight="High",
            score_impact=0.0
        ))

    # HDR-02: From display-name contains a brand/exec name whose implied domain != actual From domain
    hdr02_triggered = False
    hdr02_evidence = "Display name shows no executive or brand impersonation anomaly"
    if from_name:
        lower_name = from_name.lower()
        # Check VIP titles
        for pat in EXECUTIVE_VIP_PATTERNS:
            if re.search(pat, lower_name):
                # If display name says CEO / Finance but from address is a generic free mail (gmail, yahoo, etc.)
                if any(free in from_domain for free in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me", "mail.com", "yandex.com"]):
                    hdr02_triggered = True
                    hdr02_evidence = f"Executive/VIP pattern '{pat}' detected in display name '{from_name}' using free email provider '{from_domain}'"
                    break
        # Check protected brand names in display name
        if not hdr02_triggered:
            for brand in settings.PROTECTED_BRANDS:
                if brand in lower_name and brand not in from_domain:
                    hdr02_triggered = True
                    hdr02_evidence = f"Brand '{brand}' claimed in display name '{from_name}' but From domain is '{from_domain}'"
                    break

    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-02",
        rule_name="Executive/Brand Display-Name Impersonation",
        triggered=hdr02_triggered,
        evidence=hdr02_evidence,
        weight="High",
        score_impact=0.20 if hdr02_triggered else 0.0
    ))

    # HDR-03: Return-Path domain != From domain (with ESP allowlist)
    hdr03_triggered = False
    hdr03_evidence = "Return-Path matches From domain or verified ESP"
    if return_path_rec and from_domain:
        ret_domain = return_path_rec.domain
        if ret_domain and ret_domain != from_domain:
            is_legit_esp = any(ret_domain.endswith(esp) for esp in LEGITIMATE_ESPS)
            if not is_legit_esp:
                hdr03_triggered = True
                hdr03_evidence = f"Return-Path domain '{ret_domain}' does not match From domain '{from_domain}' and is not a known ESP"
    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-03",
        rule_name="Return-Path Domain Mismatch",
        triggered=hdr03_triggered,
        evidence=hdr03_evidence,
        weight="Medium",
        score_impact=0.12 if hdr03_triggered else 0.0
    ))

    # HDR-04: Message-ID domain unrelated to From/sending infra
    hdr04_triggered = False
    hdr04_evidence = "Message-ID domain is consistent with sender"
    if msg_id_rec and msg_id_rec.domain and from_domain:
        m_dom = msg_id_rec.domain
        if m_dom != from_domain and not any(m_dom.endswith(esp) for esp in LEGITIMATE_ESPS):
            hdr04_triggered = True
            hdr04_evidence = f"Message-ID domain '{m_dom}' is unrelated to From domain '{from_domain}'"
    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-04",
        rule_name="Message-ID Domain Discrepancy",
        triggered=hdr04_triggered,
        evidence=hdr04_evidence,
        weight="Medium",
        score_impact=0.10 if hdr04_triggered else 0.0
    ))

    # HDR-05: Duplicate/conflicting header instances of From, Date, Message-ID
    dup_headers = []
    for h in ["From", "Date", "Message-ID", "Subject"]:
        raw_list = headers.get(h, [])
        if isinstance(raw_list, list) and len(raw_list) > 1:
            dup_headers.append(f"{h} (x{len(raw_list)})")
    
    hdr05_triggered = len(dup_headers) > 0
    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-05",
        rule_name="Duplicate/Conflicting Critical Headers",
        triggered=hdr05_triggered,
        evidence=f"Duplicate headers found: {', '.join(dup_headers)}" if hdr05_triggered else "All critical RFC headers are single instances",
        weight="High",
        score_impact=0.18 if hdr05_triggered else 0.0
    ))

    # HDR-06: Date header in future or inconsistent with Received timestamps
    hdr06_triggered = False
    hdr06_evidence = "Header Date is chronologically valid"
    if date_str:
        try:
            parsed_date = parsedate_to_datetime(date_str)
            now = datetime.now(timezone.utc)
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            delta = (parsed_date - now).total_seconds()
            if delta > 900:  # > 15 mins in future
                hdr06_triggered = True
                hdr06_evidence = f"Date header is in the future by {int(delta/60)} minutes: {date_str}"
        except Exception:
            hdr06_triggered = True
            hdr06_evidence = f"Date header has unparseable/invalid RFC format: {date_str}"

    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-06",
        rule_name="Date Header Inconsistency / Future Timestamp",
        triggered=hdr06_triggered,
        evidence=hdr06_evidence,
        weight="Medium",
        score_impact=0.10 if hdr06_triggered else 0.0
    ))

    # HDR-07: Missing expected headers entirely (Message-ID, Date)
    missing = []
    if not msg_id_rec:
        missing.append("Message-ID")
    if not date_str:
        missing.append("Date")
    hdr07_triggered = len(missing) > 0
    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-07",
        rule_name="Missing Standard RFC Headers",
        triggered=hdr07_triggered,
        evidence=f"Missing standard headers: {', '.join(missing)}" if hdr07_triggered else "Standard RFC headers present",
        weight="Low",
        score_impact=0.08 if hdr07_triggered else 0.0
    ))

    # HDR-08: Character-level homoglyph/Unicode confusable in From display name or domain
    hdr08_triggered = False
    confusable_parts = []
    if has_unicode_confusables(from_name):
        confusable_parts.append(f"display name '{from_name}'")
    if has_unicode_confusables(from_domain):
        confusable_parts.append(f"domain '{from_domain}'")

    if confusable_parts:
        hdr08_triggered = True
        hdr08_evidence = f"Unicode homoglyphs / mixed scripts detected in {', '.join(confusable_parts)}"
    else:
        hdr08_evidence = "No Unicode homoglyphs or mixed scripts detected in sender identity"

    results.append(HeaderAnomalyRuleResult(
        rule_id="HDR-08",
        rule_name="Unicode Homoglyph / Confusable in Sender Identity",
        triggered=hdr08_triggered,
        evidence=hdr08_evidence,
        weight="High",
        score_impact=0.22 if hdr08_triggered else 0.0
    ))

    return results
