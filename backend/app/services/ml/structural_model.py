import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from backend.app.schemas.canonical import (
    AuthResult, HeaderAnomalyRuleResult, RelayHop, DomainIntelligenceRecord,
    UrlAnalysisRecord, AttachmentAnalysisRecord, GeoLocationRecord, StructuralFeatureExplanation
)

FEATURE_NAMES = [
    "spf_fail", "dkim_unaligned", "dmarc_fail", "num_header_anomalies",
    "reply_to_mismatch", "display_name_spoof", "domain_age_risk", "domain_lookalike",
    "url_mismatch", "ip_literal_url", "url_max_risk", "attachment_macro",
    "attachment_ext_mismatch", "relay_untrusted_present", "sender_is_vpn_tor", "sender_is_bulletproof"
]

FEATURE_WEIGHTS = {
    "dmarc_fail": (0.22, "DMARC authentication and alignment failed"),
    "reply_to_mismatch": (0.18, "Reply-To address points to an unrelated external domain"),
    "display_name_spoof": (0.16, "Executive or brand identity spoofed in sender display name"),
    "domain_lookalike": (0.15, "Domain is a typosquatted lookalike of a protected brand"),
    "domain_age_risk": (0.14, "Sender domain was registered recently (high age decay risk)"),
    "attachment_ext_mismatch": (0.18, "Attachment has executable magic bytes or double extension"),
    "attachment_macro": (0.16, "Malicious VBA macro triggers detected in Office attachment"),
    "url_mismatch": (0.15, "Phishing link mismatch: Anchor text disguises destination URL"),
    "ip_literal_url": (0.12, "Embedded URL uses raw IP address instead of registered domain"),
    "spf_fail": (0.10, "SPF verification failed for sending IP"),
    "dkim_unaligned": (0.08, "DKIM signature is missing or signed by unrelated third-party domain"),
    "sender_is_bulletproof": (0.14, "Sending infrastructure hosted on known bulletproof/malicious ASN"),
    "sender_is_vpn_tor": (0.10, "Originating IP routed through anonymizing VPN / TOR exit node"),
    "relay_untrusted_present": (0.08, "Relay chain contains untrusted or forged SMTP hops"),
    "num_header_anomalies": (0.10, "Multiple RFC header discrepancies and violations"),
    "url_max_risk": (0.12, "High-risk URL redirection chain detected in email body")
}


def extract_structural_features(
    auth: AuthResult,
    header_anomalies: List[HeaderAnomalyRuleResult],
    relay_hops: List[RelayHop],
    domains: List[DomainIntelligenceRecord],
    urls: List[UrlAnalysisRecord],
    attachments: List[AttachmentAnalysisRecord],
    geo: Optional[GeoLocationRecord] = None
) -> Dict[str, float]:
    features = {f: 0.0 for f in FEATURE_NAMES}

    # Auth
    if auth.spf.result in ("fail", "softfail", "permerror"):
        features["spf_fail"] = 1.0
    if not any(d.valid and d.aligned for d in auth.dkim):
        features["dkim_unaligned"] = 1.0
    if auth.dmarc.result == "fail":
        features["dmarc_fail"] = 1.0

    # Header anomalies
    triggered_rules = [r for r in header_anomalies if r.triggered]
    features["num_header_anomalies"] = min(1.0, len(triggered_rules) / 3.0)

    for r in triggered_rules:
        if r.rule_id == "HDR-01":
            features["reply_to_mismatch"] = 1.0
        elif r.rule_id == "HDR-02":
            features["display_name_spoof"] = 1.0

    # Domain
    if domains:
        max_age_risk = max([d.age_risk_score for d in domains], default=0.0)
        max_lookalike = max([d.lookalike_score for d in domains], default=0.0)
        features["domain_age_risk"] = max_age_risk
        features["domain_lookalike"] = max_lookalike

    # URLs
    if urls:
        features["url_mismatch"] = 1.0 if any(u.is_mismatch for u in urls) else 0.0
        features["ip_literal_url"] = 1.0 if any(u.is_ip_literal for u in urls) else 0.0
        features["url_max_risk"] = max([u.url_risk_score for u in urls], default=0.0)

    # Attachments
    if attachments:
        features["attachment_macro"] = 1.0 if any(a.has_macros for a in attachments) else 0.0
        features["attachment_ext_mismatch"] = 1.0 if any(a.is_extension_mismatch or a.is_double_extension for a in attachments) else 0.0

    # Relay
    if relay_hops:
        features["relay_untrusted_present"] = 1.0 if any(h.trust_level in ("UNTRUSTED", "POTENTIALLY_FORGED") for h in relay_hops) else 0.0

    # Geo / ASN
    if geo:
        if geo.is_vpn or geo.is_tor:
            features["sender_is_vpn_tor"] = 1.0
        if geo.reputation == "MALICIOUS" or (geo.asn and geo.asn in (200019, 39351)):
            features["sender_is_bulletproof"] = 1.0

    return features


def predict_structural_risk(features: Dict[str, float]) -> Tuple[float, List[StructuralFeatureExplanation]]:
    score = 0.0
    explanations: List[StructuralFeatureExplanation] = []

    for feat_name, feat_val in features.items():
        if feat_val > 0 and feat_name in FEATURE_WEIGHTS:
            weight, human_desc = FEATURE_WEIGHTS[feat_name]
            contribution = round(feat_val * weight, 3)
            score += contribution
            explanations.append(StructuralFeatureExplanation(
                feature=feat_name,
                value=round(feat_val, 2),
                contribution=contribution,
                human_readable=human_desc
            ))

    # Normalize score between 0.0 and 1.0
    normalized_score = round(min(1.0, max(0.02, score)), 3)

    # Sort explanations by highest contribution (SHAP waterfall)
    explanations.sort(key=lambda x: x.contribution, reverse=True)

    return normalized_score, explanations
