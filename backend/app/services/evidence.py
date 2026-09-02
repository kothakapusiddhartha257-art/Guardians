import os
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from backend.app.core.config import settings, STORAGE_DIR
from backend.app.schemas.canonical import ChainOfCustodyEntry


def save_raw_evidence(email_id: str, raw_bytes: bytes) -> str:
    email_dir = STORAGE_DIR / email_id
    email_dir.mkdir(parents=True, exist_ok=True)
    file_path = email_dir / "original.eml"
    with open(file_path, "wb") as f:
        f.write(raw_bytes)
    return str(file_path)


def read_raw_evidence(email_id: str) -> Optional[bytes]:
    file_path = STORAGE_DIR / email_id / "original.eml"
    if file_path.exists():
        with open(file_path, "rb") as f:
            return f.read()
    return None


def generate_custody_entry(
    case_id: str,
    email_id: Optional[str],
    action: str,
    actor: str,
    details: Dict[str, Any],
    prev_hash: Optional[str] = None
) -> ChainOfCustodyEntry:
    timestamp_str = datetime.utcnow().isoformat() + "Z"
    
    if not prev_hash:
        prev_hash = "GENESIS_0000000000000000000000000000000000000000000000000000000000000000"

    # Compute tamper-evident chained hash
    payload = f"{prev_hash}|{case_id}|{email_id or ''}|{action}|{actor}|{timestamp_str}|{str(details)}"
    current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    return ChainOfCustodyEntry(
        action=action,
        actor=actor,
        timestamp=timestamp_str,
        sha256_hash=current_hash,
        prev_hash=prev_hash,
        current_hash=current_hash,
        details=details
    )


def redact_pii(text: str) -> str:
    if not text:
        return ""
    # Credit Card Numbers (13-19 digits)
    redacted = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CREDIT_CARD]', text)
    # US SSN / National IDs (xxx-xx-xxxx)
    redacted = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_NATIONAL_ID]', redacted)
    # API tokens / Bearer headers
    redacted = re.sub(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED_TOKEN]', redacted)
    # International phone numbers
    redacted = re.sub(r'\+?\b[0-9]{1,4}?[-.\s]?\(?[0-9]{1,4}?\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b', '[REDACTED_PHONE]', redacted)
    return redacted
