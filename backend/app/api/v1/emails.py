import io
import base64
from typing import Optional, List
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from backend.app.schemas.canonical import (
    FullEmailInvestigationBundle, ThreeAxisScore, AuthResult, RelayHop,
    DomainIntelligenceRecord, UrlAnalysisRecord, AttachmentAnalysisRecord
)
from backend.app.services.pipeline import execute_analysis_dag, INVESTIGATION_CACHE
from backend.app.services.graph_service import graph_engine
from backend.app.services.reporting import generate_forensic_pdf_report, generate_stix_bundle
from backend.app.services.evidence import read_raw_evidence

router = APIRouter(prefix="/emails", tags=["Emails"])


class EmailIngestRequest(BaseModel):
    raw_eml_base64: Optional[str] = None
    raw_mime: Optional[str] = None
    gmail_message_id: Optional[str] = None
    case_id: Optional[str] = None


@router.post("", status_code=202)
async def upload_and_analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    case_id: Optional[str] = Form(None)
):
    if file:
        content_bytes = await file.read()
    elif raw_content:
        content_bytes = raw_content.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Must provide an .eml file or raw MIME text")

    if len(content_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    bundle = await execute_analysis_dag(content_bytes, case_id=case_id)

    return {
        "status": "COMPLETE",
        "email_id": bundle.email.email_id,
        "case_id": bundle.case_id,
        "report_id": bundle.report_id or bundle.email.email_id,
        "sha256": bundle.email.sha256,
        "threat_score": bundle.risk_score.threat_score,
        "classification": bundle.risk_score.classification
    }


@router.post("/ingest", status_code=200)
async def ingest_raw_email(req: EmailIngestRequest):
    """Direct forensic ingestion endpoint for browser extension and automated gateways."""
    if req.raw_eml_base64:
        try:
            content_bytes = base64.b64decode(req.raw_eml_base64)
        except Exception:
            padded = req.raw_eml_base64 + "=" * (-len(req.raw_eml_base64) % 4)
            content_bytes = base64.urlsafe_b64decode(padded)
    elif req.raw_mime:
        content_bytes = req.raw_mime.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Must provide either raw_eml_base64 or raw_mime string.")

    if len(content_bytes) == 0:
        raise HTTPException(status_code=400, detail="Email payload is empty")

    bundle = await execute_analysis_dag(content_bytes, case_id=req.case_id)

    claimed_dom = bundle.email.headers_normalized.from_address.domain if bundle.email.headers_normalized.from_address else ""
    actual_dom = bundle.email.headers_normalized.return_path.domain if bundle.email.headers_normalized.return_path else claimed_dom
    
    from_rec = bundle.email.headers_normalized.from_address
    if from_rec:
        from_addr = f"{from_rec.display_name} <{from_rec.address}>" if from_rec.display_name else from_rec.address
    else:
        from_addr = bundle.email.from_address

    signals = []
    if bundle.risk_score.top_reasons:
        signals = [r.human_readable for r in bundle.risk_score.top_reasons[:3]]
    elif bundle.indicators:
        signals = [ind.description for ind in bundle.indicators[:3]]
    else:
        signals = ["Anomalous sender infrastructure", "Cryptographic authentication check", "Intent classification pattern"]

    subj = bundle.email.headers_normalized.subject if bundle.email.headers_normalized.subject else bundle.email.headers_raw.get("subject", "(No Subject)")

    return {
        "status": "COMPLETE",
        "email_id": bundle.email.email_id,
        "case_id": bundle.case_id,
        "report_id": bundle.report_id or bundle.email.email_id,
        "gmail_message_id": req.gmail_message_id or "",
        "subject": subj,
        "from_address": from_addr,
        "claimed_domain": claimed_dom,
        "actual_domain": actual_dom,
        "threat_score": bundle.risk_score.threat_score,
        "infra_confidence": bundle.risk_score.infrastructure_confidence,
        "attribution_confidence": bundle.risk_score.attribution_confidence,
        "classification": bundle.risk_score.classification,
        "explanation_summary": f"Detected {bundle.risk_score.classification} threat pattern with {int(bundle.risk_score.threat_score * 100)}% severity.",
        "key_signals": signals,
        "auth": {
            "spf": bundle.auth.spf.result.upper() if bundle.auth.spf else "NONE",
            "dkim": "PASS" if any(d.valid for d in bundle.auth.dkim) else ("FAIL" if bundle.auth.dkim else "NONE"),
            "dmarc": bundle.auth.dmarc.result.upper() if bundle.auth.dmarc else "NONE",
            "arc": "PASS" if bundle.auth.arc.chain_valid else ("FAIL" if bundle.auth.arc.present else "NONE")
        },
        "origin_ip": bundle.geo_locations[0].ip if bundle.geo_locations else "",
        "origin_country": bundle.geo_locations[0].country if bundle.geo_locations else "",
        "origin_city": bundle.geo_locations[0].city if bundle.geo_locations else "",
        "relay_hops_count": len(bundle.relay_hops),
        "related_cases_count": bundle.related_cases_count,
        "related_case_ids": bundle.related_case_ids,
        "investigation_url": f"/investigation?id={bundle.report_id or bundle.email.email_id}",
        "created_at": bundle.chain_of_custody[0].timestamp if bundle.chain_of_custody else ""
    }


@router.get("/{email_id}")
async def get_full_email_investigation(email_id: str) -> FullEmailInvestigationBundle:
    if email_id in INVESTIGATION_CACHE:
        return INVESTIGATION_CACHE[email_id]
    for bundle in INVESTIGATION_CACHE.values():
        if (bundle.report_id and bundle.report_id == email_id) or \
           bundle.case_id == email_id or \
           bundle.email.email_id == email_id or \
           bundle.email.sha256 == email_id:
            return bundle
    raise HTTPException(status_code=404, detail="Email investigation not found")


@router.get("/{email_id}/status")
async def get_email_status(email_id: str):
    if email_id in INVESTIGATION_CACHE:
        return {
            "status": "COMPLETE",
            "stages_complete": [
                "evidence_preservation", "mime_header_parsing",
                "forensics_and_intelligence_fanout", "structural_ml_and_anomaly",
                "graph_correlation", "risk_fusion_and_scoring", "completed"
            ],
            "stages_pending": []
        }
    return {"status": "NOT_FOUND"}


@router.get("/{email_id}/headers")
async def get_email_headers(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    return {
        "headers_raw": bundle.email.headers_raw,
        "headers_normalized": bundle.email.headers_normalized,
        "anomalies": bundle.header_anomalies
    }


@router.get("/{email_id}/authentication")
async def get_email_authentication(email_id: str) -> AuthResult:
    bundle = await get_full_email_investigation(email_id)
    return bundle.auth


@router.get("/{email_id}/relay")
async def get_email_relay_hops(email_id: str) -> List[RelayHop]:
    bundle = await get_full_email_investigation(email_id)
    return bundle.relay_hops


@router.get("/{email_id}/geolocation")
async def get_email_geolocation(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    return bundle.geo_locations


@router.get("/{email_id}/domains")
async def get_email_domains(email_id: str) -> List[DomainIntelligenceRecord]:
    bundle = await get_full_email_investigation(email_id)
    return bundle.domains


@router.get("/{email_id}/urls")
async def get_email_urls(email_id: str) -> List[UrlAnalysisRecord]:
    bundle = await get_full_email_investigation(email_id)
    return bundle.urls


@router.get("/{email_id}/attachments")
async def get_email_attachments(email_id: str) -> List[AttachmentAnalysisRecord]:
    bundle = await get_full_email_investigation(email_id)
    return bundle.attachments


@router.get("/{email_id}/report.pdf")
async def download_pdf_report(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    pdf_bytes = generate_forensic_pdf_report(bundle)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=TraceGuard_Report_{bundle.case_id}.pdf"}
    )


@router.get("/{email_id}/stix.json")
async def download_stix_bundle(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    stix_dict = generate_stix_bundle(bundle)
    return JSONResponse(content=stix_dict)


@router.get("/{email_id}/raw.eml")
async def download_raw_eml(email_id: str):
    eml_bytes = read_raw_evidence(email_id)
    if not eml_bytes:
        raise HTTPException(status_code=404, detail="Raw evidence .eml not found on disk")
    return Response(
        content=eml_bytes,
        media_type="message/rfc822",
        headers={"Content-Disposition": f"attachment; filename=evidence_{email_id}.eml"}
    )
