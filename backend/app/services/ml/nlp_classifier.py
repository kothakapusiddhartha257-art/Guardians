import re
from typing import Dict, Any, List, Tuple
from backend.app.schemas.canonical import NlpClassificationResult, ParsedEmail

URGENCY_PATTERNS = [
    r"\b(urgently|urgent|immediately|within 24 hours|within 1 hour|action required|final notice|immediate response|account suspension|suspended|terminate)\b",
    r"\b(do not ignore|critical alert|security notice|unauthorized access detected|password expiring today)\b"
]

AUTHORITY_PATTERNS = [
    r"\b(chief executive officer|ceo|cfo|cto|coo|president|board of directors|executive office)\b",
    r"\b(it support|it department|helpdesk admin|security operations|system administrator|payroll manager)\b"
]

FINANCIAL_PATTERNS = [
    r"\b(wire transfer|bank transfer|update bank details|remittance|vendor payment|routing number|swift code)\b",
    r"\b(unpaid invoice|overdue payment|outstanding balance|gift card|crypto|bitcoin|payroll direct deposit)\b"
]

CREDENTIAL_PATTERNS = [
    r"\b(verify your password|confirm your login|click here to login|validate your account|reset password)\b",
    r"\b(keep your access active|re-authenticate|mfa verification|update credentials|log in to view)\b"
]


def extract_highlighted_spans(text: str, category: str, patterns: List[str]) -> List[Dict[str, Any]]:
    spans = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            spans.append({
                "category": category,
                "text": match.group(0),
                "start": match.start(),
                "end": match.end(),
                "explanation": f"{category.replace('_', ' ').title()} cue: '{match.group(0)}'"
            })
    return spans


def classify_text_intent(parsed: ParsedEmail, structured_signals: Dict[str, Any] = {}) -> NlpClassificationResult:
    subject = parsed.headers_normalized.subject or ""
    body = parsed.body_text or ""
    full_text = f"{subject}\n{body}"

    # Extract highlighted linguistic cues
    urgency_spans = extract_highlighted_spans(full_text, "urgency", URGENCY_PATTERNS)
    authority_spans = extract_highlighted_spans(full_text, "authority_impersonation", AUTHORITY_PATTERNS)
    financial_spans = extract_highlighted_spans(full_text, "financial_request", FINANCIAL_PATTERNS)
    credential_spans = extract_highlighted_spans(full_text, "credential_harvest", CREDENTIAL_PATTERNS)

    all_spans = urgency_spans + authority_spans + financial_spans + credential_spans

    has_urgency = len(urgency_spans) > 0
    has_authority = len(authority_spans) > 0
    has_financial = len(financial_spans) > 0
    has_credential = len(credential_spans) > 0

    # Rule-augmented probability estimation
    scores = {
        "LEGITIMATE": 0.05,
        "SPAM": 0.05,
        "PHISHING": 0.10,
        "BEC": 0.05,
        "CREDENTIAL_HARVEST": 0.05,
        "INVOICE_FRAUD": 0.05,
        "IMPERSONATION": 0.05
    }

    if has_authority and has_financial:
        scores["BEC"] += 0.65
        scores["INVOICE_FRAUD"] += 0.20
        scores["IMPERSONATION"] += 0.15
    elif has_financial and ("invoice" in full_text.lower() or "payment" in full_text.lower()):
        scores["INVOICE_FRAUD"] += 0.70
        scores["BEC"] += 0.20
    elif has_credential:
        scores["CREDENTIAL_HARVEST"] += 0.75
        scores["PHISHING"] += 0.25
    elif has_authority and not has_financial:
        scores["IMPERSONATION"] += 0.60
        scores["PHISHING"] += 0.30
    elif has_urgency and ("click" in full_text.lower() or "link" in full_text.lower()):
        scores["PHISHING"] += 0.65
        scores["SPAM"] += 0.15
    elif "unsubscribe" in full_text.lower() and not has_urgency and not has_financial:
        scores["SPAM"] += 0.60
        scores["LEGITIMATE"] += 0.30
    else:
        scores["LEGITIMATE"] = 0.85

    # Normalize distribution
    total = sum(scores.values())
    probs = {k: round(v / total, 3) for k, v in scores.items()}

    # Winner class
    winner_class = max(probs, key=probs.get)
    confidence = probs[winner_class]

    return NlpClassificationResult(
        classification=winner_class,
        confidence=confidence,
        probabilities=probs,
        urgency_detected=has_urgency,
        authority_impersonation=has_authority,
        financial_request=has_financial,
        credential_harvest_cue=has_credential,
        highlighted_spans=all_spans[:10]  # top spans
    )
