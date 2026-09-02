from abc import ABC, abstractmethod
from typing import Dict, Any, Callable, Optional, Awaitable
from backend.app.schemas.gateway import RawMessage


class EmailProvider(ABC):
    """Abstract Base Class for all mailbox ingestion providers (IMAP, Gmail, Outlook, Simulator)."""

    def __init__(self, display_name: str = "Default Mailbox"):
        self.display_name = display_name
        self.is_connected = False
        self.is_listening = False
        self.on_new_message_callback: Optional[Callable[[RawMessage], Awaitable[None]]] = None

    @abstractmethod
    async def connect(self, credentials: Dict[str, Any]) -> bool:
        """Connect and authenticate to mailbox provider using credentials."""
        pass

    @abstractmethod
    async def start_listening(self, on_new_message: Callable[[RawMessage], Awaitable[None]]) -> None:
        """Register push/IDLE/webhook/polling and invoke on_new_message(RawMessage) per new incoming email."""
        pass

    @abstractmethod
    async def stop_listening(self) -> None:
        """Gracefully terminate IDLE/polling/webhook connections."""
        pass

    @abstractmethod
    async def get_raw_message(self, provider_message_id: str) -> RawMessage:
        """Fetch full raw RFC 822 MIME bytes for a specific provider message ID."""
        pass

    @abstractmethod
    async def apply_action(self, provider_message_id: str, action: str) -> bool:
        """Apply response action ('deliver', 'flag', 'quarantine') reversibly, never hard delete."""
        pass

    @abstractmethod
    async def renew_subscription(self) -> None:
        """Renew Gmail watch() or Graph webhook subscription to prevent expiry."""
        pass
