from app.config import SCORE_WEIGHTS
from app.models.schemas import AnalysisResponse, HeaderAnalysisResult, ScoreReason
from app.scoring.rules import RULE_DESCRIPTIONS


def score_analysis(analysis: HeaderAnalysisResult, errors: list[str]) -> AnalysisResponse:
    rules: list[str] = []
    for auth_name in ("spf", "dkim", "dmarc"):
        result = getattr(analysis.auth, auth_name)
        if result in ("fail", "none") or (auth_name == "spf" and result == "softfail"):
            rules.append(f"{auth_name}_{result}")
    rules.extend(analysis.domain_mismatches)
    if analysis.is_typosquat:
        rules.append("typosquat")
    if analysis.has_timestamp_anomaly:
        rules.append("timestamp_anomaly")
    reasons = [ScoreReason(rule=rule, points=SCORE_WEIGHTS[rule], description=RULE_DESCRIPTIONS[rule]) for rule in rules]
    score = min(100, sum(reason.points for reason in reasons))
    verdict = "safe" if score < 30 else "suspicious" if score < 70 else "critical"
    return AnalysisResponse(verdict=verdict, score=score, reasons=reasons, header_analysis=analysis, processing_errors=errors)
