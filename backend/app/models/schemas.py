from typing import Optional

from pydantic import BaseModel


class ReceivedHop(BaseModel):
    hop_index: int
    ip: Optional[str]
    is_private_ip: bool
    claimed_hostname: Optional[str]
    timestamp_utc: Optional[str]


class AuthResult(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    source: str


class HeaderAnalysisResult(BaseModel):
    from_address: Optional[str]
    from_domain: Optional[str]
    reply_to_domain: Optional[str]
    return_path_domain: Optional[str]
    message_id_domain: Optional[str]
    subject: Optional[str]
    date_header: Optional[str]
    sender_ip: Optional[str]
    received_chain: list[ReceivedHop]
    auth: AuthResult
    is_typosquat: bool
    typosquat_target: Optional[str]
    domain_mismatches: list[str]
    has_timestamp_anomaly: bool


class ScoreReason(BaseModel):
    rule: str
    points: int
    description: str


class AnalysisResponse(BaseModel):
    verdict: str
    score: int
    reasons: list[ScoreReason]
    header_analysis: HeaderAnalysisResult
    processing_errors: list[str]
