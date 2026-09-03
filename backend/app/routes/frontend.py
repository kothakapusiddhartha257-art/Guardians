"""Small compatibility layer between the TRACEGUARD UI and the P1 analyzer.

The analyzer's public contract remains `/analyze`; these endpoints retain an
uploaded result in memory only long enough for the browser investigation view.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parseaddr
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.config import MAX_EMAIL_BYTES
from app.routes.analyze import _analyze
from app.services.local_threat_engine import analyze_local_threats

router = APIRouter(prefix="/api/v1", tags=["frontend"])
_investigations: dict[str, dict] = {}
INVESTIGATION_DIR = Path(__file__).resolve().parents[2] / "data" / "investigations"
INVESTIGATION_DIR.mkdir(parents=True, exist_ok=True)


def store_investigation(email_id: str, bundle: dict) -> None:
    """Persist local reports so browser links survive an API reload/restart."""
    _investigations[email_id] = bundle
    (INVESTIGATION_DIR / f"{email_id}.json").write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")


def load_investigation(email_id: str) -> dict | None:
    bundle = _investigations.get(email_id)
    if bundle:
        return bundle
    path = INVESTIGATION_DIR / f"{email_id}.json"
    if not path.is_file():
        return None
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
        _investigations[email_id] = bundle
        return bundle
    except (OSError, json.JSONDecodeError):
        return None


async def _read_input(file: UploadFile | None, raw_content: str | None) -> bytes:
    if file is not None:
        raw = await file.read(MAX_EMAIL_BYTES + 1)
    elif raw_content and raw_content.strip():
        raw = raw_content.encode("utf-8", errors="replace")
    else:
        raise HTTPException(422, "Provide an .eml file or non-empty raw email content.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(413, "Email exceeds the 10MB limit.")
    return raw


def _body(raw: bytes) -> str:
    # The detailed P1 contract deliberately analyzes headers. This preview is
    # display-only and avoids attempting HTML rendering in the browser.
    text = raw.decode("utf-8", errors="replace")
    return text.split("\n\n", 1)[1].strip() if "\n\n" in text else ""


def _ui_bundle(email_id: str, raw: bytes, result: dict) -> dict:
    analysis = result["header_analysis"]
    local = analyze_local_threats(raw)
    local_points = sum(signal["points"] for signal in local["signals"])
    combined_score = min(100, result["score"] + local_points)
    score = combined_score / 100
    classification = "CRITICAL" if combined_score >= 70 else "SUSPICIOUS" if combined_score >= 30 else "SAFE"
    from_name, from_address = parseaddr(analysis.get("from_address") or "")
    auth = analysis["auth"]
    reasons = result["reasons"] + local["signals"]
    triggered = {reason["rule"]: reason["description"] for reason in reasons}
    anomalies = [
        {"rule_id": rule, "name": rule.replace("_", " ").title(), "triggered": rule in triggered,
         "description": triggered.get(rule, "No anomaly detected by this check.")}
        for rule in ("spf_fail", "dkim_fail", "dmarc_fail", "typosquat", "timestamp_anomaly")
    ]
    hops = [
        {"hop_index": hop["hop_index"] + 1, "ip": hop.get("ip") or "Unavailable",
         "from_mta": hop.get("claimed_hostname") or "Unknown", "by_mta": "SMTP relay",
         "is_trust_frontier": not hop.get("is_private_ip", False),
         "trust_classification": "TRUSTED" if hop.get("is_private_ip") else "UNTRUSTED"}
        for hop in analysis["received_chain"]
    ]
    ip_intelligence = local["ip_intelligence"]
    if hops and ip_intelligence.get("status") == "available":
        hops[0]["reverse_dns"] = ip_intelligence.get("reverse_dns")
        hops[0]["asn"] = ip_intelligence.get("asn")
    geo = ip_intelligence.get("geoip", {})
    geo_locations = ([{"ip": ip_intelligence["ip"], "country": geo.get("country") or "Unknown",
                       "city": geo.get("city") or "Unknown", "asn": ip_intelligence.get("asn", {}).get("asn") or "Unknown",
                       "latitude": geo.get("latitude"), "longitude": geo.get("longitude")}]
                     if geo.get("status") == "available" else [])
    domain_values = [analysis.get(key) for key in ("from_domain", "reply_to_domain", "return_path_domain", "message_id_domain")]
    domains = [{"domain": value} for value in dict.fromkeys(value for value in domain_values if value)]
    now = datetime.now(timezone.utc).isoformat()
    return {
        "report_id": f"REP-{email_id[:8].upper()}", "case_id": f"CAS-{email_id[:8].upper()}",
        "related_cases_count": 0,
        "email": {"email_id": email_id, "sha256": sha256(raw).hexdigest(),
                  "body_text_sanitized": local["body"],
                  "headers_normalized": {"subject": analysis.get("subject"), "date": analysis.get("date_header"),
                      "from_address": {"display_name": from_name, "address": from_address or analysis.get("from_address")}}},
        "risk_score": {"threat_score": score, "classification": classification,
                       "infrastructure_confidence": 1 - score, "attribution_confidence": score if reasons else 0,
                       "reasons": [{"rule": item["rule"], "human_readable": item["description"],
                                    "contribution": item["points"] / 100} for item in reasons]},
        "auth": {name: {"result": auth.get(name, "unknown"), "domain": analysis.get("from_domain")}
                 for name in ("spf", "dkim", "dmarc")} | {"arc": {"result": "unknown"}},
        "header_anomalies": anomalies, "relay_hops": hops, "geo_locations": geo_locations, "ip_intelligence": ip_intelligence, "domains": domains,
        "urls": local["urls"], "attachments": local["attachments"], "nlp": local["nlp"],
        "chain_of_custody": [{"event": "Email analyzed", "timestamp": now, "actor": "P1 header analyzer"}],
        "processing_errors": result.get("processing_errors", []),
    }


@router.post("/emails")
async def upload_email(file: UploadFile | None = File(None), raw_content: str | None = Form(None)) -> dict:
    raw = await _read_input(file, raw_content)
    result = _analyze(raw).model_dump()
    email_id = uuid4().hex
    bundle = _ui_bundle(email_id, raw, result)
    store_investigation(email_id, bundle)
    return {"email_id": email_id, "verdict": bundle["risk_score"]["classification"].lower(),
            "score": round(bundle["risk_score"]["threat_score"] * 100)}


@router.get("/emails/{email_id}")
async def get_email(email_id: str) -> dict:
    # This route is declared before the UI's `/emails/live` route, so keep the
    # analyzer-only live collection from being interpreted as an email ID.
    if email_id == "live":
        return []
    bundle = load_investigation(email_id)
    if not bundle:
        raise HTTPException(404, "Investigation not found. Upload the email again; results are kept in memory only.")
    return bundle


@router.get("/emails/{email_id}/graph")
async def get_email_graph(email_id: str) -> dict:
    if not load_investigation(email_id):
        raise HTTPException(404, "Investigation not found.")
    return {"nodes": [], "edges": []}


@router.get("/network-intelligence/{ip}")
async def network_intelligence(ip: str) -> dict:
    """Inspect a single IP for the dedicated network-intelligence view."""
    from app.services.network_intelligence import inspect_sender_network
    return inspect_sender_network(ip)


# These platform endpoints let the supplied UI run in analyzer-only mode. They
# intentionally report no connected mailbox or live feed; P1 has no OAuth or
# mailbox-ingestion service behind it.
@router.get("/mailboxes")
async def get_mailboxes() -> list:
    return []


@router.get("/emails/live")
async def get_live_emails() -> list:
    return []


@router.get("/dashboard/summary")
async def dashboard_summary() -> dict:
    return {"active_threats_count": 0, "quarantined_count": 0, "critical_count": 0,
            "suspicious_count": 0, "safe_count": 0, "average_threat_score": 0,
            "total_analyzed": len(_investigations), "frontiers_breached": 0}


@router.get("/dashboard/trend")
@router.get("/dashboard/recent")
@router.get("/cases")
@router.get("/campaigns")
async def empty_collection() -> list:
    return []


@router.get("/oauth/gmail/status")
@router.get("/gmail/status")
async def mailbox_status() -> dict:
    return {"connected": False, "status": "analyzer-only"}


@router.get("/gmail/results")
async def gmail_results() -> list:
    return []
