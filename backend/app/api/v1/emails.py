import io
from typing import Optional, List
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Response
from fastapi.responses import JSONResponse, StreamingResponse

from backend.app.schemas.canonical import (
    FullEmailInvestigationBundle, ThreeAxisScore, AuthResult, RelayHop,
    DomainIntelligenceRecord, UrlAnalysisRecord, AttachmentAnalysisRecord
)
from backend.app.services.pipeline import execute_analysis_dag, INVESTIGATION_CACHE
from backend.app.services.graph_service import graph_engine
from backend.app.services.reporting import generate_forensic_pdf_report, generate_stix_bundle
from backend.app.services.evidence import read_raw_evidence

router = APIRouter(prefix="/emails", tags=["Emails"])


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
        "sha256": bundle.email.sha256,
        "threat_score": bundle.risk_score.threat_score,
        "classification": bundle.risk_score.classification
    }


@router.get("/{email_id}")
async def get_full_email_investigation(email_id: str) -> FullEmailInvestigationBundle:
    if email_id not in INVESTIGATION_CACHE:
        raise HTTPException(status_code=404, detail="Email investigation not found")
    return INVESTIGATION_CACHE[email_id]


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


@router.get("/{email_id}/risk")
async def get_email_risk_scores(email_id: str) -> ThreeAxisScore:
    bundle = await get_full_email_investigation(email_id)
    return bundle.risk_score


@router.get("/{email_id}/graph")
async def get_email_subgraph(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    subgraph = graph_engine.export_subgraph_for_visualization(email_id)
    return subgraph


@router.get("/{email_id}/report.pdf")
async def download_pdf_report(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    pdf_bytes = generate_forensic_pdf_report(bundle)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=TRACEGUARD_{bundle.case_id}.pdf"}
    )


@router.get("/{email_id}/report.json")
async def download_json_evidence_bundle(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    return bundle.model_dump()


@router.get("/{email_id}/report.stix")
async def download_stix_bundle(email_id: str):
    bundle = await get_full_email_investigation(email_id)
    stix_dict = generate_stix_bundle(bundle)
    return JSONResponse(
        content=stix_dict,
        headers={"Content-Disposition": f"attachment; filename=TRACEGUARD_{bundle.case_id}.stix.json"}
    )


@router.get("/{email_id}/raw.eml")
async def download_original_eml(email_id: str):
    raw = read_raw_evidence(email_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Raw .eml evidence not found")
    return Response(
        content=raw,
        media_type="message/rfc822",
        headers={"Content-Disposition": f"attachment; filename=evidence_{email_id}.eml"}
    )
