from typing import Dict, Any, List, Tuple
from backend.app.schemas.gateway import PolicyConfig
from backend.app.schemas.canonical import FullEmailInvestigationBundle

ACTION_SEVERITY_RANK = {
    "DELIVER": 1,
    "FLAG": 2,
    "QUARANTINE": 3
}

# Default runtime policy configuration (modifiable live by analyst via API)
CURRENT_POLICY = PolicyConfig()


def get_verdict_for_threat_score(threat_score_pct: int, thresholds: Dict[str, List[int]]) -> str:
    for verdict, (low, high) in thresholds.items():
        if low <= threat_score_pct <= high:
            return verdict
    return "MALICIOUS" if threat_score_pct >= 80 else "SAFE"


def map_verdict_to_base_action(verdict: str) -> str:
    if verdict == "MALICIOUS":
        return "QUARANTINE"
    elif verdict in ("SUSPICIOUS", "LOW_RISK"):
        return "FLAG"
    return "DELIVER"


def evaluate_policy_and_overrides(bundle: FullEmailInvestigationBundle) -> Tuple[str, str, List[Dict[str, Any]]]:
    """
    Evaluates sensitivity thresholds and Catastrophic Override Rules.
    Returns: (verdict: str, action: str, triggered_rules: List[Dict])
    """
    threat_pct = int(bundle.risk_score.threat_score * 100)
    verdict = get_verdict_for_threat_score(threat_pct, CURRENT_POLICY.thresholds)
    base_action = map_verdict_to_base_action(verdict)

    triggered_overrides: List[Dict[str, Any]] = []

    if not CURRENT_POLICY.enable_overrides:
        return verdict, base_action, triggered_overrides

    # Extract raw structural signals from the bundle
    has_dmarc_fail = bundle.auth.dmarc.result == "fail"
    has_exec_impersonation = any(r.rule_id == "HDR-02" and r.triggered for r in bundle.header_anomalies) or bundle.nlp.authority_impersonation
    has_reply_to_mismatch = any(r.rule_id == "HDR-01" and r.triggered for r in bundle.header_anomalies)
    has_financial_request = bundle.nlp.financial_request
    has_exec_masquerade = any(a.is_extension_mismatch or a.is_double_extension for a in bundle.attachments)
    has_ip_literal = any(u.is_ip_literal for u in bundle.urls)
    has_anchor_mismatch = any(u.is_mismatch for u in bundle.urls)
    has_homoglyph = any(d.has_unicode_confusable or d.is_lookalike for d in bundle.domains)
    min_domain_age = min([d.age_days for d in bundle.domains if d.age_days is not None], default=3650)

    # 1. DMARC Fail + Executive Impersonation
    if has_dmarc_fail and has_exec_impersonation:
        triggered_overrides.append({
            "rule_id": "OR-01",
            "name": "DMARC Authentication Failure with Executive Spoofing",
            "min_action": "QUARANTINE",
            "evidence": "Sender forged executive identity and failed domain cryptographic DMARC verification"
        })

    # 2. Disguised Executable Payload (MZ bytes disguised as PDF/Doc)
    if has_exec_masquerade:
        triggered_overrides.append({
            "rule_id": "OR-02",
            "name": "Disguised Executable Masquerade (MZ Header)",
            "min_action": "QUARANTINE",
            "evidence": "Attachment exhibits executable binary magic bytes with a deceptive document extension"
        })

    # 3. IP-Literal URL with Anchor Mismatch
    if has_ip_literal and has_anchor_mismatch:
        triggered_overrides.append({
            "rule_id": "OR-03",
            "name": "IP-Literal Destination with Deceptive Link Text",
            "min_action": "QUARANTINE",
            "evidence": "Anchor text displays legitimate corporate portal but links directly to an unauthenticated raw IP"
        })

    # 4. Young Domain (< 15 days) + Homoglyph / Typosquat
    if min_domain_age < 15 and has_homoglyph:
        triggered_overrides.append({
            "rule_id": "OR-04",
            "name": "Fresh Lookalike Domain Registration (<15 Days)",
            "min_action": "QUARANTINE",
            "evidence": f"Domain was registered {min_domain_age} days ago and utilizes visual homoglyph character confusion"
        })

    # 5. Reply-To Mismatch + Financial Wire Transfer Request
    if has_reply_to_mismatch and has_financial_request:
        triggered_overrides.append({
            "rule_id": "OR-05",
            "name": "Reply-To Redirection with Urgent Financial Directive",
            "min_action": "QUARANTINE",
            "evidence": "External Reply-To address redirects response for urgent wire transfer instructions"
        })

    # Apply override precedence: A catastrophic override escalates action to QUARANTINE/FLAG regardless of score
    final_action = base_action
    for override in triggered_overrides:
        min_act = override["min_action"]
        if ACTION_SEVERITY_RANK.get(min_act, 1) > ACTION_SEVERITY_RANK.get(final_action, 1):
            final_action = min_act
            if final_action == "QUARANTINE":
                verdict = "MALICIOUS"

    return verdict, final_action, triggered_overrides
