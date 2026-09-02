import hashlib
from datetime import datetime
from typing import Optional, Tuple
from backend.app.schemas.gateway import RawMessage
from backend.app.services.evidence import save_raw_evidence, generate_custody_entry

# In-memory idempotency cache to guarantee zero duplicate cases
SEEN_PROVIDER_MESSAGES = set()


def check_and_capture_evidence(raw_msg: RawMessage, email_id: str, case_id: str) -> Tuple[bool, str, str]:
    """
    Idempotency check and immutable evidence capture.
    Returns: (is_new_message: bool, sha256_hash: str, evidence_path: str)
    """
    dedup_key = f"{raw_msg.provider}:{raw_msg.provider_message_id}"

    if dedup_key in SEEN_PROVIDER_MESSAGES:
        # Duplicate webhook or IDLE notification - skip to prevent duplicate case creation
        return False, "", ""

    SEEN_PROVIDER_MESSAGES.add(dedup_key)

    # Compute SHA-256 hash over exact original bytes
    sha256_hash = hashlib.sha256(raw_msg.raw_rfc822).hexdigest()

    # Store raw .eml immutably in object/filesystem storage
    evidence_path = save_raw_evidence(email_id, raw_msg.raw_rfc822)

    return True, sha256_hash, evidence_path
