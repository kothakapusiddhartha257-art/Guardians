import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from fastapi import WebSocket

from backend.app.schemas.gateway import RawMessage, EmailMessageRecord, MailboxConnectionResponse
from backend.app.services.email_ingestion.base import EmailProvider
from backend.app.services.email_ingestion.imap import IMAPProvider
from backend.app.services.email_ingestion.gmail import GmailProvider
from backend.app.services.email_ingestion.outlook import OutlookProvider
from backend.app.services.email_ingestion.simulator import SimulatorProvider
from backend.app.services.email_ingestion.evidence_capture import check_and_capture_evidence
from backend.app.services.pipeline import execute_analysis_dag, INVESTIGATION_CACHE
from backend.app.services.response_engine import evaluate_policy_and_overrides


class EmailMonitorOrchestrator:
    """Orchestrates Mailbox Ingestion, Phase 1 DAG execution, Policy Engine decisions, and Live WebSockets."""

    def __init__(self):
        self.providers: Dict[str, EmailProvider] = {}
        self.active_connections: Dict[str, MailboxConnectionResponse] = {}
        self.live_email_records: List[EmailMessageRecord] = []
        self.websocket_subscribers: Set[WebSocket] = set()

        # Initialize default demo simulator provider on startup
        sim_id = "mailbox-simulator-01"
        sim_provider = SimulatorProvider("Gateway Demo Simulator")
        self.providers[sim_id] = sim_provider
        self.active_connections[sim_id] = MailboxConnectionResponse(
            id=sim_id,
            provider="simulator",
            display_name="Live Threat Gateway (Active Monitoring)",
            status="listening",
            monitored_count=14,
            created_at=datetime.utcnow().isoformat() + "Z"
        )

    async def connect_mailbox(self, provider_type: str, display_name: str, credentials: Dict[str, Any]) -> MailboxConnectionResponse:
        conn_id = f"mailbox-{uuid.uuid4().hex[:8]}"

        if provider_type == "imap":
            provider = IMAPProvider(display_name)
        elif provider_type == "gmail":
            provider = GmailProvider(display_name)
        elif provider_type == "outlook":
            provider = OutlookProvider(display_name)
        else:
            provider = SimulatorProvider(display_name)

        success = await provider.connect(credentials)
        if not success:
            raise ValueError(f"Failed to authenticate with {provider_type.upper()} server.")

        await provider.start_listening(self.handle_incoming_raw_message)

        resp = MailboxConnectionResponse(
            id=conn_id,
            provider=provider_type,
            display_name=display_name,
            status="listening",
            monitored_count=0,
            created_at=datetime.utcnow().isoformat() + "Z"
        )

        self.providers[conn_id] = provider
        self.active_connections[conn_id] = resp
        return resp

    async def disconnect_mailbox(self, conn_id: str) -> bool:
        if conn_id in self.providers:
            await self.providers[conn_id].stop_listening()
            del self.providers[conn_id]
        if conn_id in self.active_connections:
            del self.active_connections[conn_id]
        return True

    async def handle_incoming_raw_message(self, raw_msg: RawMessage) -> Optional[EmailMessageRecord]:
        """Core Ingestion Pipeline Trigger: Ingests -> Preserves -> Analyzes -> Decides -> Acts -> Broadcasts."""
        email_id = str(uuid.uuid4())
        case_id = f"CASE-2026-{uuid.uuid4().hex[:5].upper()}"

        # 1. Idempotency Check & Evidence Capture
        is_new, sha256_hash, _ = check_and_capture_evidence(raw_msg, email_id=email_id, case_id=case_id)
        if not is_new:
            print(f"[Gateway] Duplicate message {raw_msg.provider_message_id} ignored.")
            return None

        # 2. Execute Phase 1 Forensic DAG Pipeline (Frozen)
        bundle = await execute_analysis_dag(raw_msg.raw_rfc822, case_id=case_id, actor=f"GATEWAY_{raw_msg.provider.upper()}")

        # 3. Evaluate Policy and Overrides
        verdict, action_taken, triggered_overrides = evaluate_policy_and_overrides(bundle)

        # 4. Apply Reversible Action on Mailbox Provider
        for provider in self.providers.values():
            try:
                await provider.apply_action(raw_msg.provider_message_id, action_taken)
            except Exception as e:
                print(f"[!] Error applying action to provider: {e}")

        # 5. Build Live Email Message Record
        sender_addr = bundle.email.headers_normalized.from_address.address if bundle.email.headers_normalized.from_address else (raw_msg.sender or "Unknown")
        subj = bundle.email.headers_normalized.subject or raw_msg.subject or "No Subject"

        # Combine SHAP top reasons and catastrophic override rules
        all_triggered = [dict(r) for r in triggered_overrides]
        for reason in bundle.risk_score.top_reasons[:3]:
            all_triggered.append({
                "rule_id": reason.feature,
                "name": reason.human_readable,
                "evidence": f"Contribution +{int(reason.contribution*100)}%"
            })

        record = EmailMessageRecord(
            id=str(uuid.uuid4()),
            provider=raw_msg.provider,
            provider_message_id=raw_msg.provider_message_id,
            message_id=bundle.email.headers_normalized.message_id.raw if bundle.email.headers_normalized.message_id else None,
            sender=sender_addr,
            recipient=raw_msg.recipient or "corporate-inbox@acme.com",
            subject=subj,
            received_at=raw_msg.received_at,
            raw_eml_hash=bundle.email.sha256,
            threat_score=bundle.risk_score.threat_score,
            infra_confidence=bundle.risk_score.infrastructure_confidence,
            attribution_confidence=bundle.risk_score.attribution_confidence,
            verdict=verdict,
            action_taken=action_taken,
            triggered_rules=all_triggered,
            analysis_status="complete",
            case_id=bundle.case_id,
            email_id=bundle.email.email_id,
            correlated_cases_count=bundle.related_cases_count,
            created_at=datetime.utcnow().isoformat() + "Z"
        )

        self.live_email_records.insert(0, record)

        # Increment monitored count
        for conn in self.active_connections.values():
            conn.monitored_count += 1

        # 6. Real-Time Broadcast over WebSocket
        await self.broadcast_websocket_event({
            "type": "NEW_LIVE_EMAIL",
            "data": record.model_dump()
        })

        return record

    async def broadcast_websocket_event(self, event_data: Dict[str, Any]):
        dead_connections = set()
        for ws in self.websocket_subscribers:
            try:
                await ws.send_json(event_data)
            except Exception:
                dead_connections.add(ws)
        self.websocket_subscribers.difference_update(dead_connections)


# Singleton instance
email_monitor = EmailMonitorOrchestrator()
