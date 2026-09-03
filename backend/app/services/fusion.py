from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.config import settings
from backend.app.schemas.canonical import (
    ThreeAxisScore, StructuralFeatureExplanation, NlpClassificationResult,
    AuthResult, HeaderAnomalyRuleResult, RelayHop, DomainIntelligenceRecord,
    UrlAnalysisRecord, AttachmentAnalysisRecord, GeoLocationRecord
)


def compute_three_axis_score(
    email_id: str,
    nlp_result: NlpClassificationResult,
    structural_score: float,
    structural_explanations: List[StructuralFeatureExplanation],
    header_anomalies: List[HeaderAnomalyRuleResult],
    relay_hops: List[RelayHop],
    domains: List[DomainIntelligenceRecord],
    urls: List[UrlAnalysisRecord],
    attachments: List[AttachmentAnalysisRecord],
    geo: Optional[GeoLocationRecord],
    behavioral_anomaly_score: float,
    cross_case_hits: int = 0
) -> ThreeAxisScore:
    weights = settings.FUSION_WEIGHTS

    # 1. Compute Sub-scores
    # NLP sub-score
    nlp_threat_weight = 0.05
    if nlp_result.classification in ("PHISHING", "BEC", "CREDENTIAL_HARVEST", "INVOICE_FRAUD", "IMPERSONATION"):
        nlp_threat_weight = max(0.85, nlp_result.confidence * 1.4)
    elif nlp_result.classification == "SPAM":
        nlp_threat_weight = 0.35

    # Header sub-score
    triggered_rules = [r for r in header_anomalies if r.triggered]
    header_score = min(1.0, sum(r.score_impact for r in triggered_rules) * 1.5)

    # URL sub-score
    url_score = max([u.url_risk_score for u in urls], default=0.0)

    # Domain sub-score
    domain_score = 0.0
    if domains:
        domain_score = max([max(d.age_risk_score, d.lookalike_score) for d in domains], default=0.0)

    # IP sub-score
    ip_score = 0.0
    if geo:
        ip_score = geo.reputation_score
        if geo.is_vpn or geo.is_tor:
            ip_score = max(ip_score, 0.70)

    # Relay sub-score
    relay_score = 0.0
    if any(h.trust_level == "POTENTIALLY_FORGED" for h in relay_hops):
        relay_score = 0.90
    elif any(h.trust_level == "UNTRUSTED" for h in relay_hops):
        relay_score = 0.60

    # Attachment sub-score
    attachment_score = max([a.risk_score for a in attachments], default=0.0)

    sub_scores = {
        "nlp": round(nlp_threat_weight, 3),
        "structural": round(structural_score, 3),
        "header": round(header_score, 3),
        "url": round(url_score, 3),
        "domain": round(domain_score, 3),
        "ip": round(ip_score, 3),
        "relay": round(relay_score, 3),
        "attachment": round(attachment_score, 3),
        "behavior": round(behavioral_anomaly_score, 3)
    }

    # 2. Weighted Late Decision-Level Monotonic Fusion
    weighted_sum = (
        weights["nlp"] * sub_scores["nlp"] +
        weights["structural"] * sub_scores["structural"] +
        weights["header"] * sub_scores["header"] +
        weights["url"] * sub_scores["url"] +
        weights["domain"] * sub_scores["domain"] +
        weights["ip"] * sub_scores["ip"] +
        weights["relay"] * sub_scores["relay"] +
        weights["attachment"] * sub_scores["attachment"] +
        weights["behavior"] * sub_scores["behavior"]
    )

    # Monotonic scaling with non-linear boost for compounding high-severity evidence
    compounding_boost = 0.0
    high_threat_signals = 0
    if sub_scores["header"] > 0.35: high_threat_signals += 1
    if sub_scores["structural"] > 0.35: high_threat_signals += 1
    if sub_scores["domain"] > 0.5: high_threat_signals += 1
    if sub_scores["nlp"] > 0.6: high_threat_signals += 1
    if sub_scores["url"] > 0.4: high_threat_signals += 1
    if sub_scores["attachment"] > 0.4: high_threat_signals += 1

    if high_threat_signals >= 3:
        compounding_boost += 0.25
    elif high_threat_signals >= 2:
        compounding_boost += 0.15

    raw_threat_score = min(1.0, max(0.02, weighted_sum + compounding_boost))

    # If legitimate without anomalies, clamp low
    if nlp_result.classification == "LEGITIMATE" and len(triggered_rules) == 0 and url_score < 0.1 and attachment_score < 0.1:
        raw_threat_score = min(raw_threat_score, 0.08)

    final_threat_score = round(raw_threat_score, 3)

    # 3. Infrastructure Confidence Calculation
    # Based on relay trust frontier depth, GeoIP accuracy radius, DNS data completeness
    trusted_hops_count = len([h for h in relay_hops if h.trust_level in ("TRUSTED", "LIKELY_TRUSTED")])
    total_hops_count = len(relay_hops)
    
    infra_conf_base = 0.85
    if total_hops_count > 0:
        frontier_ratio = trusted_hops_count / total_hops_count
        infra_conf_base = 0.60 + 0.35 * frontier_ratio
    
    if geo and geo.accuracy_radius_km > 100:
        infra_conf_base -= 0.15

    final_infra_conf = round(min(1.0, max(0.20, infra_conf_base)), 3)

    # 4. Attribution Confidence Calculation
    # Distinct from infrastructure location: how strongly linked to known actor/campaign infrastructure
    # Penalized heavily if IP is a generic cloud/VPN/TOR host unless shared across documented cases
    attr_conf_base = 0.15
    if cross_case_hits > 0:
        attr_conf_base = min(0.95, 0.35 + (0.15 * cross_case_hits))
    elif geo and not geo.is_hosting and not geo.is_vpn and not geo.is_tor:
        attr_conf_base = 0.40  # Direct dedicated IP

    final_attr_conf = round(attr_conf_base, 3)

    # 5. Determine Classification and Confidence
    final_classification = nlp_result.classification
    if final_threat_score < 0.25 and final_classification != "LEGITIMATE":
        final_classification = "LEGITIMATE"
    elif final_threat_score > 0.70 and final_classification == "LEGITIMATE":
        final_classification = "SUSPICIOUS"

    # 6. Assemble Ranked Top Reasons (SHAP + Rule Explanations)
    combined_reasons: List[StructuralFeatureExplanation] = list(structural_explanations)

    for rule in triggered_rules:
        # Check if already covered in structural explanations
        if not any(r.human_readable == rule.evidence for r in combined_reasons):
            combined_reasons.append(StructuralFeatureExplanation(
                feature=rule.rule_id,
                value=rule.weight,
                contribution=rule.score_impact,
                human_readable=rule.evidence
            ))

    if nlp_result.urgency_detected:
        combined_reasons.append(StructuralFeatureExplanation(
            feature="nlp_urgency",
            value=True,
            contribution=0.12,
            human_readable="Urgent psychological pressure phrasing detected in email body"
        ))
    if nlp_result.financial_request:
        combined_reasons.append(StructuralFeatureExplanation(
            feature="nlp_financial",
            value=True,
            contribution=0.15,
            human_readable="Financial transfer / banking redirection request identified"
        ))

    combined_reasons.sort(key=lambda x: x.contribution, reverse=True)

    return ThreeAxisScore(
        email_id=email_id,
        threat_score=final_threat_score,
        infrastructure_confidence=final_infra_conf,
        attribution_confidence=final_attr_conf,
        classification=final_classification,
        classification_confidence=nlp_result.confidence,
        top_reasons=combined_reasons[:8],
        sub_scores=sub_scores,
        model_version="fusion-v1.2.0",
        computed_at=datetime.utcnow().isoformat() + "Z"
    )
