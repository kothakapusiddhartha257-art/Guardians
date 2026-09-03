from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from app.config import MAX_EMAIL_BYTES
from app.header_analysis.auth_checks import check_authentication
from app.header_analysis.extractor import extract_headers
from app.header_analysis.received_chain import parse_received_chain
from app.header_analysis.spoof_checks import domain_mismatches, timestamp_anomaly, typosquat
from app.ingestion.parser import EmailParseError, parse_email
from app.models.schemas import AnalysisResponse, HeaderAnalysisResult
from app.scoring.engine import score_analysis

router = APIRouter()


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message})


def _analyze(raw: bytes) -> AnalysisResponse:
    try:
        message = parse_email(raw)
    except EmailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    errors: list[str] = []
    fields = extract_headers(message)
    chain, sender_ip = parse_received_chain(message)
    auth = check_authentication(message, fields["from_domain"], errors)
    mismatches = domain_mismatches(fields["from_domain"], reply_to_domain=fields["reply_to_domain"], return_path_domain=fields["return_path_domain"], message_id_domain=fields["message_id_domain"])
    is_typosquat, target = typosquat(fields["from_domain"])
    analysis = HeaderAnalysisResult(**fields, sender_ip=sender_ip, received_chain=chain, auth=auth,
                                    is_typosquat=is_typosquat, typosquat_target=target,
                                    domain_mismatches=mismatches, has_timestamp_anomaly=timestamp_anomaly(message, chain))
    return score_analysis(analysis, errors)


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: Request, file: Annotated[UploadFile | None, File()] = None) -> AnalysisResponse:
    if file is not None:
        raw = await file.read(MAX_EMAIL_BYTES + 1)
        if len(raw) > MAX_EMAIL_BYTES:
            return _error(413, "Uploaded email exceeds the 10MB limit.")
        try:
            return _analyze(raw)
        except HTTPException as exc:
            return _error(exc.status_code, str(exc.detail))
    try:
        payload = await request.json()
    except Exception as exc:
        return _error(422, "Provide an .eml file or a JSON raw_email field.")
    raw_email = payload.get("raw_email") if isinstance(payload, dict) else None
    if not isinstance(raw_email, str) or not raw_email.strip():
        return _error(422, "Provide an .eml file or a non-empty raw_email field.")
    raw = raw_email.encode("utf-8", errors="replace")
    if len(raw) > MAX_EMAIL_BYTES:
        return _error(413, "Email exceeds the 10MB limit.")
    try:
        return _analyze(raw)
    except HTTPException as exc:
        return _error(exc.status_code, str(exc.detail))


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
