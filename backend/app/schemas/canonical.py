from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EmailAddressRecord(BaseModel):
    display_name: Optional[str] = None
    address: str
    domain: str


class MessageIdRecord(BaseModel):
    raw: str
    domain: Optional[str] = None


class HeaderNormalized(BaseModel):
    from_address: Optional[EmailAddressRecord] = Field(default=None, alias="from")
    reply_to: Optional[EmailAddressRecord] = None
    return_path: Optional[EmailAddressRecord] = None
    message_id: Optional[MessageIdRecord] = None
    date: Optional[str] = None
    subject: Optional[str] = None

    class Config:
        populate_by_name = True


class UrlRecord(BaseModel):
    displayed: Optional[str] = None
    actual_href: str


class AttachmentRecord(BaseModel):
    filename: str
    mime: str
    size: int
    sha256: str
    data_base64: Optional[str] = None


class ParsedEmail(BaseModel):
    email_id: str
    sha256: str
    raw_size_bytes: int
    mime_structure: List[str] = []
    headers_raw: Dict[str, Any] = {}
    headers_normalized: HeaderNormalized
    received_chain_raw: List[str] = []
    body_text: str = ""
    body_html: str = ""
    urls: List[UrlRecord] = []
    attachments: List[AttachmentRecord] = []


class IndicatorRecord(BaseModel):
    indicator_id: str
    email_id: str
    type: str  # IP | DOMAIN | URL | FILE_HASH | EMAIL_ADDRESS | ASN
    value: str
    role: Optional[str] = None
    risk_score: float = 0.0
    confidence: float = 0.0
    source: str = "internal"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    seen_in_case_ids: List[str] = []


class RelayHop(BaseModel):
    email_id: Optional[str] = None
    hop_number: int
    from_host_claimed: Optional[str] = None
    by_host_claimed: Optional[str] = None
    ip_extracted: Optional[str] = None
    protocol: Optional[str] = None
    timestamp_claimed: Optional[str] = None
    timestamp_delta_seconds: Optional[int] = None
    trust_level: str  # TRUSTED | LIKELY_TRUSTED | UNTRUSTED | POTENTIALLY_FORGED | PARSE_FAILED
    trust_reasoning: List[str] = []
    rdns: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    asn_org: Optional[str] = None


class SpfResult(BaseModel):
    result: str  # pass | fail | softfail | neutral | none | permerror | temperror
    domain_checked: Optional[str] = None
    ip_checked: Optional[str] = None
    record_text: Optional[str] = None
    explanation: Optional[str] = None


class DkimResult(BaseModel):
    selector: Optional[str] = None
    domain: Optional[str] = None
    valid: bool = False
    aligned: bool = False
    details: Optional[str] = None


class DmarcResult(BaseModel):
    policy: str = "none"  # none | quarantine | reject | not_found
    spf_aligned: bool = False
    dkim_aligned: bool = False
    result: str = "none"  # pass | fail | none
    record_text: Optional[str] = None
    explanation: Optional[str] = None


class ArcResult(BaseModel):
    present: bool = False
    chain_valid: bool = False
    hop_count: int = 0
    details: Optional[str] = None


class AuthResult(BaseModel):
    spf: SpfResult
    dkim: List[DkimResult] = []
    dmarc: DmarcResult
    arc: ArcResult


class HeaderAnomalyRuleResult(BaseModel):
    rule_id: str
    rule_name: str
    triggered: bool
    evidence: str
    weight: str  # High | Medium | Low
    score_impact: float


class GeoLocationRecord(BaseModel):
    ip: str
    country: Optional[str] = "Unknown"
    region: Optional[str] = None
    city: Optional[str] = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: int = 50
    asn: Optional[int] = None
    asn_org: Optional[str] = "Unknown ASN"
    is_vpn: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    reputation: str = "UNKNOWN"  # SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN
    reputation_score: float = 0.0
    infrastructure_confidence: float = 0.8
    actor_location_confidence: float = 0.2


class DomainIntelligenceRecord(BaseModel):
    domain: str
    registrable_domain: str
    age_days: Optional[int] = None
    age_risk_score: float = 0.0
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    is_lookalike: bool = False
    lookalike_target: Optional[str] = None
    lookalike_score: float = 0.0
    is_punycode: bool = False
    punycode_decoded: Optional[str] = None
    has_unicode_confusable: bool = False
    has_mixed_script: bool = False
    dns_records: Dict[str, Any] = {}
    risk_reasons: List[str] = []


class UrlAnalysisRecord(BaseModel):
    displayed_text: Optional[str] = None
    actual_href: str
    is_mismatch: bool = False
    redirect_chain: List[str] = []
    final_domain: str = ""
    is_shortener: bool = False
    is_ip_literal: bool = False
    has_userinfo_obfuscation: bool = False
    url_risk_score: float = 0.0
    risk_reasons: List[str] = []


class AttachmentAnalysisRecord(BaseModel):
    filename: str
    claimed_mime: str
    magic_detected_mime: str
    size_bytes: int
    sha256: str
    is_extension_mismatch: bool = False
    is_double_extension: bool = False
    shannon_entropy: float = 0.0
    has_macros: bool = False
    macro_keywords: List[str] = []
    pdf_has_javascript: bool = False
    pdf_has_openaction: bool = False
    archive_depth: int = 0
    risk_score: float = 0.0
    risk_reasons: List[str] = []


class NlpClassificationResult(BaseModel):
    classification: str  # LEGITIMATE | SPAM | PHISHING | BEC | CREDENTIAL_HARVEST | INVOICE_FRAUD | IMPERSONATION
    confidence: float
    probabilities: Dict[str, float]
    urgency_detected: bool
    authority_impersonation: bool
    financial_request: bool
    credential_harvest_cue: bool
    highlighted_spans: List[Dict[str, Any]] = []


class StructuralFeatureExplanation(BaseModel):
    feature: str
    value: Any
    contribution: float
    human_readable: str


class ThreeAxisScore(BaseModel):
    email_id: str
    threat_score: float
    infrastructure_confidence: float
    attribution_confidence: float
    classification: str
    classification_confidence: float
    top_reasons: List[StructuralFeatureExplanation] = []
    sub_scores: Dict[str, float] = {}
    model_version: str = "fusion-v1.2.0"
    computed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class ChainOfCustodyEntry(BaseModel):
    id: Optional[int] = None
    action: str  # UPLOADED | PARSED | ANALYZED | VIEWED | EXPORTED | STATUS_CHANGED
    actor: str
    timestamp: str
    sha256_hash: Optional[str] = None
    prev_hash: Optional[str] = None
    current_hash: Optional[str] = None
    details: Dict[str, Any] = {}


class Case(BaseModel):
    case_id: str
    title: Optional[str] = None
    status: str = "NEW"  # NEW | UNDER_INVESTIGATION | ESCALATED | CLOSED_CONFIRMED | CLOSED_FALSE_POSITIVE
    severity: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    email_ids: List[str] = []
    linked_indicator_ids: List[str] = []
    campaign_id: Optional[str] = None
    assigned_analyst: Optional[str] = "analyst_01"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    chain_of_custody: List[ChainOfCustodyEntry] = []


class CampaignRecord(BaseModel):
    campaign_id: str
    name: str
    description: Optional[str] = None
    first_seen: str
    last_seen: str
    email_count: int = 0
    case_ids: List[str] = []
    shared_indicators: List[IndicatorRecord] = []
    threat_type: str = "PHISHING"
    similarity_threshold: float = 0.75


class FullEmailInvestigationBundle(BaseModel):
    email: ParsedEmail
    case_id: str
    report_id: Optional[str] = None
    risk_score: ThreeAxisScore
    auth: AuthResult
    header_anomalies: List[HeaderAnomalyRuleResult]
    relay_hops: List[RelayHop]
    geo_locations: List[GeoLocationRecord]
    domains: List[DomainIntelligenceRecord]
    urls: List[UrlAnalysisRecord]
    attachments: List[AttachmentAnalysisRecord]
    nlp: NlpClassificationResult
    chain_of_custody: List[ChainOfCustodyEntry]
    related_cases_count: int = 0
    related_case_ids: List[str] = []
