import json
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index, BigInteger
)
from backend.app.core.config import settings

Base = declarative_base()

class CaseModel(Base):
    __tablename__ = "cases"
    case_id = Column(String, primary_key=True)
    title = Column(String, nullable=True)
    status = Column(String, nullable=False, default="NEW")
    severity = Column(String, nullable=False, default="LOW")
    campaign_id = Column(String, nullable=True)
    assigned_analyst = Column(String, nullable=True, default="analyst_01")
    created_at = Column(DateTime, default=datetime.utcnow)

    emails = relationship("EmailModel", back_populates="case", cascade="all, delete-orphan")
    custody_entries = relationship("ChainOfCustodyModel", back_populates="case", cascade="all, delete-orphan")


class EmailModel(Base):
    __tablename__ = "emails"
    email_id = Column(String, primary_key=True)
    case_id = Column(String, ForeignKey("cases.case_id"), nullable=False)
    sha256 = Column(String, unique=True, nullable=False, index=True)
    message_id = Column(String, nullable=True)
    subject = Column(Text, nullable=True)
    from_address = Column(String, nullable=True)
    from_domain = Column(String, nullable=True, index=True)
    reply_to = Column(String, nullable=True)
    return_path = Column(String, nullable=True)
    received_at = Column(DateTime, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    raw_object_key = Column(String, nullable=False)
    raw_headers = Column(JSON, nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)

    case = relationship("CaseModel", back_populates="emails")
    artifacts = relationship("AnalysisArtifactModel", back_populates="email", cascade="all, delete-orphan")
    indicators = relationship("IndicatorModel", back_populates="email", cascade="all, delete-orphan")
    hops = relationship("RelayHopModel", back_populates="email", cascade="all, delete-orphan")
    risk = relationship("RiskScoreModel", back_populates="email", uselist=False, cascade="all, delete-orphan")


class AnalysisArtifactModel(Base):
    __tablename__ = "analysis_artifacts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(String, ForeignKey("emails.email_id"), nullable=False, index=True)
    stage_name = Column(String, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    payload = Column(JSON, nullable=False)
    computed_at = Column(DateTime, default=datetime.utcnow)

    email = relationship("EmailModel", back_populates="artifacts")


class IndicatorModel(Base):
    __tablename__ = "indicators"
    indicator_id = Column(String, primary_key=True)
    email_id = Column(String, ForeignKey("emails.email_id"), nullable=False, index=True)
    type = Column(String, nullable=False)  # IP | DOMAIN | URL | FILE_HASH | EMAIL_ADDRESS | ASN
    value = Column(String, nullable=False, index=True)
    role = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    source = Column(String, default="internal")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    email = relationship("EmailModel", back_populates="indicators")

    __table_args__ = (
        Index("idx_indicators_type_value", "type", "value"),
    )


class RelayHopModel(Base):
    __tablename__ = "relay_hops"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(String, ForeignKey("emails.email_id"), nullable=False, index=True)
    hop_number = Column(Integer, nullable=False)
    from_host_claimed = Column(String, nullable=True)
    by_host_claimed = Column(String, nullable=True)
    ip_extracted = Column(String, nullable=True, index=True)
    protocol = Column(String, nullable=True)
    timestamp_claimed = Column(DateTime, nullable=True)
    timestamp_delta_seconds = Column(Integer, nullable=True)
    trust_level = Column(String, nullable=False)
    trust_reasoning = Column(JSON, nullable=True)
    rdns = Column(String, nullable=True)

    email = relationship("EmailModel", back_populates="hops")


class GeoLocationModel(Base):
    __tablename__ = "geo_locations"
    ip = Column(String, primary_key=True)
    country = Column(String, nullable=True)
    region = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    accuracy_radius_km = Column(Integer, default=50)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String, nullable=True)
    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_hosting = Column(Boolean, default=False)
    reputation = Column(String, default="UNKNOWN")
    reputation_score = Column(Float, default=0.0)
    updated_at = Column(DateTime, default=datetime.utcnow)


class RiskScoreModel(Base):
    __tablename__ = "risk_scores"
    email_id = Column(String, ForeignKey("emails.email_id"), primary_key=True)
    threat_score = Column(Float, nullable=False)
    infrastructure_confidence = Column(Float, nullable=False)
    attribution_confidence = Column(Float, nullable=False)
    classification = Column(String, nullable=True)
    classification_confidence = Column(Float, nullable=True)
    top_reasons = Column(JSON, nullable=True)
    sub_scores = Column(JSON, nullable=True)
    model_version = Column(String, default="fusion-v1.2.0")
    computed_at = Column(DateTime, default=datetime.utcnow)

    email = relationship("EmailModel", back_populates="risk")


class ChainOfCustodyModel(Base):
    __tablename__ = "chain_of_custody"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey("cases.case_id"), nullable=False, index=True)
    email_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sha256_hash = Column(String, nullable=True)
    prev_hash = Column(String, nullable=True)
    current_hash = Column(String, nullable=True)
    details = Column(JSON, nullable=True)

    case = relationship("CaseModel", back_populates="custody_entries")


class UserModel(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="ANALYST")  # VIEWER | ANALYST | ADMIN
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=True)
    username = Column(String, nullable=True)
    action = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    details = Column(JSON, nullable=True)


class CampaignModel(Base):
    __tablename__ = "campaigns"
    campaign_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    threat_type = Column(String, default="PHISHING")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    email_count = Column(Integer, default=0)
    case_ids = Column(JSON, default=list)
    shared_indicators = Column(JSON, default=list)
    similarity_threshold = Column(Float, default=0.75)


class EmailMessageModel(Base):
    __tablename__ = "email_messages"
    id = Column(String, primary_key=True)
    provider = Column(String, nullable=False)
    provider_message_id = Column(String, nullable=False)
    message_id = Column(String, nullable=True)
    sender = Column(String, nullable=True)
    recipient = Column(String, nullable=True)
    subject = Column(Text, nullable=True)
    received_at = Column(DateTime, default=datetime.utcnow)
    raw_eml_hash = Column(String, nullable=False)
    threat_score = Column(Float, default=0.0)
    infra_confidence = Column(Float, default=0.0)
    attribution_confidence = Column(Float, default=0.0)
    verdict = Column(String, nullable=False, default="SAFE")
    action_taken = Column(String, nullable=False, default="DELIVER")
    triggered_rules = Column(JSON, default=list)
    analysis_status = Column(String, default="complete")
    case_id = Column(String, nullable=True)
    email_id = Column(String, nullable=True)
    correlated_cases_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_email_messages_provider_msg_id", "provider", "provider_message_id", unique=True),
    )


class MailboxConnectionModel(Base):
    __tablename__ = "mailbox_connections"
    id = Column(String, primary_key=True)
    provider = Column(String, nullable=False)
    display_name = Column(String, nullable=False)
    credentials_ref = Column(String, nullable=False)
    status = Column(String, default="connected")
    watch_expires_at = Column(DateTime, nullable=True)
    monitored_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


# Database engine setup
engine = create_async_engine(settings.DATABASE_URL, echo=False)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with async_session_factory() as session:
        yield session
