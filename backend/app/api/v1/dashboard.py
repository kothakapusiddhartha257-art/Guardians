from typing import Dict, Any, List
from fastapi import APIRouter
from backend.app.services.pipeline import ACTIVE_CASES_DB, INVESTIGATION_CACHE

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_dashboard_summary():
    total_emails = len(INVESTIGATION_CACHE)
    cases = list(ACTIVE_CASES_DB.values())
    
    high_risk_count = sum(1 for inv in INVESTIGATION_CACHE.values() if inv.risk_score.threat_score > 0.70)
    active_cases = sum(1 for c in cases if c["status"] in ("NEW", "UNDER_INVESTIGATION", "ESCALATED"))
    
    return {
        "emails_analyzed": total_emails,
        "high_risk_threats": high_risk_count,
        "active_cases": active_cases,
        "campaigns_detected": 3,
        "avg_analysis_latency_sec": 1.45,
        "dmarc_failures": sum(1 for inv in INVESTIGATION_CACHE.values() if inv.auth.dmarc.result == "fail"),
        "homoglyphs_detected": sum(1 for inv in INVESTIGATION_CACHE.values() if any(d.has_unicode_confusable or d.is_lookalike for d in inv.domains))
    }


@router.get("/trend")
async def get_dashboard_trend(range: str = "7d"):
    # Time series data for Recharts line/area charts
    return [
        {"date": "2026-08-25", "phishing": 12, "bec": 4, "clean": 85},
        {"date": "2026-08-26", "phishing": 18, "bec": 6, "clean": 92},
        {"date": "2026-08-27", "phishing": 15, "bec": 8, "clean": 105},
        {"date": "2026-08-28", "phishing": 25, "bec": 11, "clean": 110},
        {"date": "2026-08-29", "phishing": 22, "bec": 9, "clean": 78},
        {"date": "2026-08-30", "phishing": 34, "bec": 14, "clean": 95},
        {"date": "2026-08-31", "phishing": 42, "bec": 19, "clean": 120}
    ]


@router.get("/recent")
async def get_recent_high_risk_emails():
    recent = []
    for eid, bundle in INVESTIGATION_CACHE.items():
        recent.append({
            "email_id": eid,
            "case_id": bundle.case_id,
            "subject": bundle.email.headers_normalized.subject or "Untitled Email",
            "from_address": bundle.email.headers_normalized.from_address.address if bundle.email.headers_normalized.from_address else "Unknown",
            "threat_score": bundle.risk_score.threat_score,
            "classification": bundle.risk_score.classification,
            "timestamp": bundle.chain_of_custody[0].timestamp if bundle.chain_of_custody else ""
        })

    # Sort descending by threat score
    return sorted(recent, key=lambda x: x["threat_score"], reverse=True)[:15]
