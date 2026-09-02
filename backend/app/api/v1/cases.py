from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from backend.app.services.pipeline import ACTIVE_CASES_DB, INVESTIGATION_CACHE

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get("")
async def list_cases(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    q: Optional[str] = Query(None)
):
    cases = list(ACTIVE_CASES_DB.values())

    if status:
        cases = [c for c in cases if c["status"].upper() == status.upper()]
    if severity:
        cases = [c for c in cases if c["severity"].upper() == severity.upper()]
    if q:
        query_l = q.lower()
        cases = [
            c for c in cases
            if query_l in c["case_id"].lower() or query_l in c.get("title", "").lower()
        ]

    return sorted(cases, key=lambda x: x.get("created_at", ""), reverse=True)


@router.get("/{case_id}")
async def get_case_detail(case_id: str):
    if case_id not in ACTIVE_CASES_DB:
        raise HTTPException(status_code=404, detail="Case not found")
    
    case_meta = ACTIVE_CASES_DB[case_id]
    email_ids = case_meta.get("email_ids", [])
    investigations = [INVESTIGATION_CACHE[eid] for eid in email_ids if eid in INVESTIGATION_CACHE]

    return {
        "case": case_meta,
        "investigations": investigations
    }


@router.patch("/{case_id}")
async def update_case(
    case_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_analyst: Optional[str] = None
):
    if case_id not in ACTIVE_CASES_DB:
        raise HTTPException(status_code=404, detail="Case not found")
    
    case = ACTIVE_CASES_DB[case_id]
    if status:
        case["status"] = status
    if severity:
        case["severity"] = severity
    if assigned_analyst:
        case["assigned_analyst"] = assigned_analyst

    return case
