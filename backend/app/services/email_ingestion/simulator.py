import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Callable, Optional, Awaitable
from backend.app.schemas.gateway import RawMessage
from backend.app.services.email_ingestion.base import EmailProvider
from backend.app.seeds.demo_emails import (
    DEMO_BEC_EMAIL, DEMO_CREDENTIAL_PHISH_EMAIL, DEMO_MALWARE_INVOICE_EMAIL, DEMO_CLEAN_FORWARDED_EMAIL
)


class SimulatorProvider(EmailProvider):
    """High-fidelity Live Inbound Threat Simulator for instant hackathon demos and testing."""

    def __init__(self, display_name: str = "Live Gateway Simulator"):
        super().__init__(display_name)
        self.is_connected = True
        self.is_listening = True

    async def connect(self, credentials: Dict[str, Any]) -> bool:
        self.is_connected = True
        return True

    async def start_listening(self, on_new_message: Callable[[RawMessage], Awaitable[None]]) -> None:
        self.on_new_message_callback = on_new_message
        self.is_listening = True

    async def stop_listening(self) -> None:
        self.is_listening = False

    async def inject_simulated_email(self, scenario_type: str = "bec") -> RawMessage:
        """Injects a real-time incoming threat message into the gateway callback."""
        msg_id = f"sim_{uuid.uuid4().hex[:8]}"
        now_str = datetime.utcnow().isoformat() + "Z"

        if scenario_type == "bec":
            eml_text = DEMO_BEC_EMAIL
            subject = "URGENT: Vendor Payment Account Change & Wire Transfer Directive"
            sender = "john.smith@acme.com"
        elif scenario_type == "credential":
            eml_text = DEMO_CREDENTIAL_PHISH_EMAIL
            subject = "Action Required: Your Office 365 Password Expires in 24 Hours"
            sender = "admin@m365-security-update.top"
        elif scenario_type == "malware":
            eml_text = DEMO_MALWARE_INVOICE_EMAIL
            subject = "Overdue Invoice #88219 - Final Notice Before Legal Action"
            sender = "invoices@overdue-billing-notice.xyz"
        else:
            eml_text = DEMO_CLEAN_FORWARDED_EMAIL
            subject = "Cybersecurity Weekly Digest #412: Zero Trust Architecture Insights"
            sender = "newsletter@cybersec-weekly.org"

        raw_msg = RawMessage(
            provider="simulator",
            provider_message_id=msg_id,
            raw_rfc822=eml_text.encode("utf-8"),
            received_at=now_str,
            sender=sender,
            recipient="sarah.c@acme.com",
            subject=subject
        )

        if self.on_new_message_callback:
            await self.on_new_message_callback(raw_msg)

        return raw_msg

    async def get_raw_message(self, provider_message_id: str) -> RawMessage:
        return RawMessage(
            provider="simulator",
            provider_message_id=provider_message_id,
            raw_rfc822=DEMO_BEC_EMAIL.encode("utf-8"),
            received_at=datetime.utcnow().isoformat() + "Z"
        )

    async def apply_action(self, provider_message_id: str, action: str) -> bool:
        print(f"[Simulator] Autonomous response action '{action.upper()}' applied to message {provider_message_id}")
        return True

    async def renew_subscription(self) -> None:
        pass
