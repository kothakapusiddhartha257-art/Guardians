from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class RawMessage(BaseModel):
    provider: str  # 'imap' | 'gmail' | 'outlook' | 'simulator'
    provider_message_id: str
    raw_rfc822: bytes
    received_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None


class MailboxConnectionRequest(BaseModel):
    provider: str  # 'imap' | 'gmail' | 'outlook' | 'simulator'
    display_name: str
    credentials: Dict[str, Any] = {}  # host, port, username, password, or oauth tokens


class MailboxConnectionResponse(BaseModel):
    id: str
    provider: str
    display_name: str
    status: str  # 'connected' | 'listening' | 'error' | 'disconnected'
    watch_expires_at: Optional[str] = None
    monitored_count: int = 0
    created_at: str


class TriggeredOverrideRule(BaseModel):
    rule_id: str
    condition: str
    min_action: str  # 'FLAG' | 'QUARANTINE'
    evidence: str


class PolicyConfig(BaseModel):
    thresholds: Dict[str, List[int]] = {
        "SAFE": [0, 39],
        "LOW_RISK": [40, 59],
        "SUSPICIOUS": [60, 79],
        "MALICIOUS": [80, 100]
    }
    enable_overrides: bool = True
    active_override_rules: List[Dict[str, Any]] = [
        {"id": "OR-01", "name": "DMARC Fail + Executive Impersonation", "condition": "dmarc_fail AND executive_impersonation", "min_action": "QUARANTINE", "enabled": True},
        {"id": "OR-02", "name": "Disguised Executable Payload (MZ Header)", "condition": "attachment_is_executable_masquerade", "min_action": "QUARANTINE", "enabled": True},
        {"id": "OR-03", "name": "IP-Literal URL with Anchor Mismatch", "condition": "url_ip_literal AND anchor_text_mismatch", "min_action": "QUARANTINE", "enabled": True},
        {"id": "OR-04", "name": "Young Domain (<15d) with Homoglyph", "condition": "domain_age_days < 15 AND homoglyph_detected", "min_action": "QUARANTINE", "enabled": True},
        {"id": "OR-05", "name": "Reply-To Mismatch + Wire Transfer Phrasing", "condition": "reply_to_mismatch AND financial_request", "min_action": "QUARANTINE", "enabled": True}
    ]


class EmailMessageRecord(BaseModel):
    id: str
    provider: str
    provider_message_id: str
    message_id: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    received_at: str
    raw_eml_hash: str
    threat_score: float
    infra_confidence: float
    attribution_confidence: float
    verdict: str  # SAFE | LOW_RISK | SUSPICIOUS | MALICIOUS
    action_taken: str  # DELIVER | FLAG | QUARANTINE
    triggered_rules: List[Dict[str, Any]] = []
    analysis_status: str = "complete"
    case_id: Optional[str] = None
    email_id: Optional[str] = None
    correlated_cases_count: int = 0
    created_at: str


class ActionOverrideRequest(BaseModel):
    action: str  # 'DELIVER' | 'FLAG' | 'QUARANTINE'
    reason: str
    analyst: str = "analyst_01"
