from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query

from backend.app.schemas.gateway import EmailMessageRecord, ActionOverrideRequest
from backend.app.services.email_monitor import email_monitor

router = APIRouter(prefix="/emails/live", tags=["Live Feed"])


@router.get("", response_model=List[EmailMessageRecord])
async def get_live_feed(
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None)
):
    records = list(email_monitor.live_email_records)

    if action:
        records = [r for r in records if r.action_taken.upper() == action.upper()]
    if verdict:
        records = [r for r in records if r.verdict.upper() == verdict.upper()]

    return records[:limit]


@router.post("/{record_id}/override-action", response_model=EmailMessageRecord)
async def override_email_action(record_id: str, req: ActionOverrideRequest):
    for r in email_monitor.live_email_records:
        if r.id == record_id or r.email_id == record_id:
            old_action = r.action_taken
            r.action_taken = req.action.upper()
            r.triggered_rules.append({
                "rule_id": "MANUAL_ANALYST_OVERRIDE",
                "name": f"Analyst {req.analyst} Override",
                "evidence": f"Changed action from {old_action} to {r.action_taken}. Reason: {req.reason}"
            })

            # Broadcast update over WebSocket
            await email_monitor.broadcast_websocket_event({
                "type": "EMAIL_ACTION_OVERRIDDEN",
                "data": r.model_dump()
            })
            return r

    raise HTTPException(status_code=404, detail="Email record not found in live gateway cache")
