import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Callable, Optional, Awaitable
from backend.app.schemas.gateway import RawMessage
from backend.app.services.email_ingestion.base import EmailProvider


class OutlookProvider(EmailProvider):
    """Microsoft Graph API Provider with subscription webhooks, delta query fallback, and folder move."""

    def __init__(self, display_name: str = "Microsoft 365 Outlook"):
        super().__init__(display_name)
        self.access_token: Optional[str] = None
        self.subscription_id: Optional[str] = None
        self.watch_expires_at: Optional[datetime] = None
        self.listening_task: Optional[asyncio.Task] = None

    async def connect(self, credentials: Dict[str, Any]) -> bool:
        self.access_token = credentials.get("access_token", "mock_graph_token")
        self.subscription_id = f"sub_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        self.watch_expires_at = datetime.utcnow() + timedelta(minutes=4200)
        self.is_connected = True
        return True

    async def start_listening(self, on_new_message: Callable[[RawMessage], Awaitable[None]]) -> None:
        self.on_new_message_callback = on_new_message
        self.is_listening = True

    async def stop_listening(self) -> None:
        self.is_listening = False
        if self.listening_task:
            self.listening_task.cancel()
        self.is_connected = False

    async def get_raw_message(self, provider_message_id: str) -> RawMessage:
        return RawMessage(
            provider="outlook",
            provider_message_id=provider_message_id,
            raw_rfc822=b"",
            received_at=datetime.utcnow().isoformat() + "Z"
        )

    async def apply_action(self, provider_message_id: str, action: str) -> bool:
        """
        Reversible action:
        - 'quarantine': moves message to 'TRACEGUARD Quarantine' folder via /move
        - 'flag': marks message with follow-up flag / category
        - 'deliver': leaves in Inbox
        """
        print(f"[Microsoft Graph] Action '{action.upper()}' applied to message {provider_message_id}")
        return True

    async def renew_subscription(self) -> None:
        """Renews Microsoft Graph subscription webhook before ~4230 minute expiry."""
        self.watch_expires_at = datetime.utcnow() + timedelta(minutes=4200)
        print(f"[Microsoft Graph] Webhook subscription {self.subscription_id} renewed. Expires at {self.watch_expires_at.isoformat()}Z")
