import uuid
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from backend.app.schemas.canonical import (
    ParsedEmail, FullEmailInvestigationBundle, IndicatorRecord, RelayHop,
    GeoLocationRecord, DomainIntelligenceRecord, UrlAnalysisRecord,
    AttachmentAnalysisRecord, ChainOfCustodyEntry
)
from backend.app.services.email_parser import parse_email_bytes
from backend.app.services.auth_forensics import run_full_authentication
from backend.app.services.header_anomaly import detect_header_anomalies
from backend.app.services.relay_tracer import reconstruct_relay_hops, get_earliest_reliable_hop
from backend.app.services.geolocation import lookup_ip_intel
from backend.app.services.domain_intelligence import analyze_domain
from backend.app.services.url_analyzer import analyze_email_urls
from backend.app.services.attachment_analyzer import analyze_email_attachments
from backend.app.services.ml.nlp_classifier import classify_text_intent
from backend.app.services.ml.structural_model import extract_structural_features, predict_structural_risk
from backend.app.services.ml.anomaly_detector import calculate_behavioral_anomaly_score
from backend.app.services.fusion import compute_three_axis_score
from backend.app.services.graph_service import graph_engine
from backend.app.services.evidence import save_raw_evidence, generate_custody_entry, redact_pii


# In-memory artifact repository for sub-millisecond response & test isolation
INVESTIGATION_CACHE: Dict[str, FullEmailInvestigationBundle] = {}
ACTIVE_CASES_DB: Dict[str, Dict[str, Any]] = {}


async def execute_analysis_dag(
    raw_bytes: bytes,
    case_id: Optional[str] = None,
    actor: str = "analyst_01",
    progress_callback: Optional[Callable[[str, int], None]] = None
) -> FullEmailInvestigationBundle:
    email_id = str(uuid.uuid4())
    if not case_id:
        case_id = f"CASE-2026-{uuid.uuid4().hex[:5].upper()}"

    # Stage 1: Evidence Preservation & Ingestion
    if progress_callback:
        progress_callback("evidence_preservation", 10)
    save_raw_evidence(email_id, raw_bytes)
    
    initial_custody = generate_custody_entry(
        case_id=case_id,
        email_id=email_id,
        action="UPLOADED",
        actor=actor,
        details={"raw_size_bytes": len(raw_bytes)}
    )

    # Stage 2: MIME & Header Parsing
    if progress_callback:
        progress_callback("mime_header_parsing", 25)
    parsed = parse_email_bytes(raw_bytes, email_id=email_id)

    # Stage 3: Parallel Fan-Out (Forensics, Intelligence, NLP)
    if progress_callback:
        progress_callback("forensics_and_intelligence_fanout", 50)

    # 3a. Relay path reconstruction
    relay_hops = reconstruct_relay_hops(parsed)
    earliest_hop = get_earliest_reliable_hop(relay_hops)
    originating_ip = earliest_hop.ip_extracted if earliest_hop else None

    # 3b. GeoIP & ASN intelligence for all hop IPs
    geo_records: List[GeoLocationRecord] = []
    seen_ips = set()
    for h in relay_hops:
        if h.ip_extracted and h.ip_extracted not in seen_ips:
            seen_ips.add(h.ip_extracted)
            g_rec = lookup_ip_intel(h.ip_extracted)
            geo_records.append(g_rec)
            # Annotate hop with geo metadata
            h.geo_country = g_rec.country
            h.geo_city = g_rec.city
            h.asn_org = g_rec.asn_org

    primary_geo = geo_records[0] if geo_records else lookup_ip_intel(originating_ip)

    # 3c. Authentication (SPF, DKIM, DMARC, ARC)
    auth_result = run_full_authentication(parsed, originating_ip=originating_ip, raw_email_bytes=raw_bytes)

    # 3d. Deterministic Header Anomalies
    header_anomalies = detect_header_anomalies(parsed)

    # 3e. Domain Intelligence
    domain_records: List[DomainIntelligenceRecord] = []
    seen_domains = set()
    domains_to_check = []
    if parsed.headers_normalized.from_address:
        domains_to_check.append(parsed.headers_normalized.from_address.domain)
    if parsed.headers_normalized.reply_to:
        domains_to_check.append(parsed.headers_normalized.reply_to.domain)
    if parsed.headers_normalized.return_path:
        domains_to_check.append(parsed.headers_normalized.return_path.domain)

    for d in domains_to_check:
        if d and d not in seen_domains:
            seen_domains.add(d)
            d_intel = analyze_domain(d)
            if d_intel:
                domain_records.append(d_intel)

    # 3f. URL and Redirect Chain Analysis
    url_records = analyze_email_urls(parsed.urls)
    for u in url_records:
        if u.final_domain and u.final_domain not in seen_domains:
            seen_domains.add(u.final_domain)
            d_intel = analyze_domain(u.final_domain)
            if d_intel:
                domain_records.append(d_intel)

    # 3g. Attachment Static Analysis
    attachment_records = analyze_email_attachments(parsed.attachments)

    # 3h. NLP Intent Classification
    nlp_result = classify_text_intent(parsed)

    # Stage 4: Fan-In Machine Learning & Anomaly Modeling
    if progress_callback:
        progress_callback("structural_ml_and_anomaly", 75)

    structural_feats = extract_structural_features(
        auth=auth_result,
        header_anomalies=header_anomalies,
        relay_hops=relay_hops,
        domains=domain_records,
        urls=url_records,
        attachments=attachment_records,
        geo=primary_geo
    )
    structural_score, structural_explanations = predict_structural_risk(structural_feats)
    behavioral_anomaly = calculate_behavioral_anomaly_score(relay_hops, primary_geo, domain_records)

    # Stage 5: Graph Intelligence & Cross-Case Correlation
    if progress_callback:
        progress_callback("graph_correlation", 85)

    graph_engine.add_email_nodes_and_edges(
        parsed=parsed,
        case_id=case_id,
        relay_hops=relay_hops,
        domains=domain_records,
        urls=url_records,
        attachments=attachment_records,
        geo_records=geo_records
    )
    cross_hits_count, correlated_case_ids, _ = graph_engine.find_cross_case_infrastructure_hits(email_id)

    # Stage 6: Late Decision-Level Risk Fusion (Three-Axis Scoring)
    if progress_callback:
        progress_callback("risk_fusion_and_scoring", 95)

    risk_score = compute_three_axis_score(
        email_id=email_id,
        nlp_result=nlp_result,
        structural_score=structural_score,
        structural_explanations=structural_explanations,
        header_anomalies=header_anomalies,
        relay_hops=relay_hops,
        domains=domain_records,
        urls=url_records,
        attachments=attachment_records,
        geo=primary_geo,
        behavioral_anomaly_score=behavioral_anomaly,
        cross_case_hits=cross_hits_count
    )

    # Final Stage: Chain of Custody & Bundle Finalization
    if progress_callback:
        progress_callback("completed", 100)

    analyzed_custody = generate_custody_entry(
        case_id=case_id,
        email_id=email_id,
        action="ANALYZED",
        actor="TRACEGUARD_ENGINE",
        details={"threat_score": risk_score.threat_score, "classification": risk_score.classification},
        prev_hash=initial_custody.current_hash
    )

    bundle = FullEmailInvestigationBundle(
        email=parsed,
        case_id=case_id,
        risk_score=risk_score,
        auth=auth_result,
        header_anomalies=header_anomalies,
        relay_hops=relay_hops,
        geo_locations=geo_records,
        domains=domain_records,
        urls=url_records,
        attachments=attachment_records,
        nlp=nlp_result,
        chain_of_custody=[initial_custody, analyzed_custody],
        related_cases_count=cross_hits_count,
        related_case_ids=correlated_case_ids
    )

    # Save to Cache
    INVESTIGATION_CACHE[email_id] = bundle
    ACTIVE_CASES_DB[case_id] = {
        "case_id": case_id,
        "title": parsed.headers_normalized.subject or "Untitled Case",
        "status": "UNDER_INVESTIGATION" if risk_score.threat_score > 0.3 else "CLOSED_CONFIRMED",
        "severity": "CRITICAL" if risk_score.threat_score > 0.85 else ("HIGH" if risk_score.threat_score > 0.6 else ("MEDIUM" if risk_score.threat_score > 0.3 else "LOW")),
        "email_ids": [email_id],
        "assigned_analyst": actor,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "latest_threat_score": risk_score.threat_score,
        "classification": risk_score.classification
    }

    return bundle
