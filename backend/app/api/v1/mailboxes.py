from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.schemas.gateway import (
    MailboxConnectionRequest, MailboxConnectionResponse, PolicyConfig, EmailMessageRecord
)
from backend.app.services.email_monitor import email_monitor
from backend.app.services.response_engine import CURRENT_POLICY

router = APIRouter(prefix="/mailboxes", tags=["Mailboxes"])


class SimulateInboundRequest(BaseModel):
    scenario: str = "bec"  # 'bec' | 'credential' | 'malware' | 'clean'


@router.get("", response_model=List[MailboxConnectionResponse])
async def list_mailboxes():
    return list(email_monitor.active_connections.values())


@router.post("/connect", response_model=MailboxConnectionResponse)
async def connect_mailbox(req: MailboxConnectionRequest):
    try:
        conn = await email_monitor.connect_mailbox(
            provider_type=req.provider,
            display_name=req.display_name,
            credentials=req.credentials
        )
        return conn
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{conn_id}")
async def disconnect_mailbox(conn_id: str):
    success = await email_monitor.disconnect_mailbox(conn_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mailbox connection not found")
    return {"status": "disconnected", "id": conn_id}


@router.get("/policy")
async def get_policy_config() -> PolicyConfig:
    return CURRENT_POLICY


@router.put("/policy")
async def update_policy_config(new_policy: PolicyConfig) -> PolicyConfig:
    global CURRENT_POLICY
    CURRENT_POLICY.thresholds = new_policy.thresholds
    CURRENT_POLICY.enable_overrides = new_policy.enable_overrides
    CURRENT_POLICY.active_override_rules = new_policy.active_override_rules
    return CURRENT_POLICY


@router.post("/simulate-incoming", response_model=EmailMessageRecord)
async def simulate_incoming_threat(req: SimulateInboundRequest):
    """Triggers an instantaneous live inbound email simulation into the gateway pipeline."""
    # Find simulator provider
    sim_provider = None
    for p in email_monitor.providers.values():
        if hasattr(p, "inject_simulated_email"):
            sim_provider = p
            break

    if not sim_provider:
        from backend.app.services.email_ingestion.simulator import SimulatorProvider
        sim_provider = SimulatorProvider("Simulated Gateway")
        sim_provider.on_new_message_callback = email_monitor.handle_incoming_raw_message

    raw_msg = await sim_provider.inject_simulated_email(req.scenario)
    record = await email_monitor.handle_incoming_raw_message(raw_msg)
    if not record:
        raise HTTPException(status_code=500, detail="Simulation failed to produce live record")
    return record
