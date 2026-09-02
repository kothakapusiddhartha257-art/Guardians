import os
import json
import base64
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError

from backend.app.core.config import BASE_DIR

logger = logging.getLogger(__name__)

OAUTH_DIR = BASE_DIR / "data" / "oauth_credentials"
OAUTH_DIR.mkdir(parents=True, exist_ok=True)

CREDENTIALS_FILE = OAUTH_DIR / "credentials.json"
TOKEN_FILE = OAUTH_DIR / "token.json"

SCOPES = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email"
]

# Default demo credentials if not yet uploaded
DEFAULT_CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID", "traceguard-demo-client-id.apps.googleusercontent.com"),
        "project_id": "traceguard-ai-soc",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", "demo_oauth_client_secret"),
        "redirect_uris": [
            "http://127.0.0.1:8000/api/v1/oauth/gmail/callback",
            "http://localhost:8000/api/v1/oauth/gmail/callback",
            "http://localhost:5173/monitoring"
        ]
    }
}


class GmailOAuthManager:
    """Manages Google OAuth 2.0 credentials, token refresh, and Gmail API / XOAUTH2 client creation."""

    def __init__(self, credentials_path: Path = CREDENTIALS_FILE, token_path: Path = TOKEN_FILE):
        self.credentials_path = credentials_path
        self.token_path = token_path
        if not self.credentials_path.exists():
            self.save_client_config(DEFAULT_CLIENT_CONFIG)

    def save_client_config(self, config_dict: Dict[str, Any]) -> None:
        with open(self.credentials_path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2)

    def get_client_config(self) -> Dict[str, Any]:
        if self.credentials_path.exists():
            try:
                with open(self.credentials_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return DEFAULT_CLIENT_CONFIG

    def get_authorization_url(self, redirect_uri: str) -> Tuple[str, str]:
        """Generates Google OAuth 2.0 authorization URL for user consent."""
        client_config = self.get_client_config()
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )
        return auth_url, state

    def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchanges authorization code for access and refresh tokens."""
        client_config = self.get_client_config()
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        flow.fetch_token(code=code)
        creds = flow.credentials

        # Extract user email address from userinfo / token if available
        user_email = "authenticated.user@gmail.com"
        try:
            oauth2_service = build("oauth2", "v2", credentials=creds)
            user_info = oauth2_service.userinfo().get().execute()
            user_email = user_info.get("email", user_email)
        except Exception:
            pass

        token_data = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
            "user_email": user_email
        }

        with open(self.token_path, "w", encoding="utf-8") as f:
            json.dump(token_data, f, indent=2)

        return token_data

    def get_valid_credentials(self) -> Optional[Credentials]:
        """Retrieves and refreshes Google OAuth 2.0 credentials if expired."""
        if not self.token_path.exists():
            return None

        try:
            with open(self.token_path, "r", encoding="utf-8") as f:
                token_data = json.load(f)

            creds = Credentials(
                token=token_data.get("token"),
                refresh_token=token_data.get("refresh_token"),
                token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=token_data.get("client_id"),
                client_secret=token_data.get("client_secret"),
                scopes=token_data.get("scopes", SCOPES)
            )

            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    token_data["token"] = creds.token
                    with open(self.token_path, "w", encoding="utf-8") as f:
                        json.dump(token_data, f, indent=2)
                except RefreshError as e:
                    logger.error(f"Failed to refresh OAuth token: {e}")
                    return None

            return creds
        except Exception as e:
            logger.error(f"Error loading credentials from {self.token_path}: {e}")
            return None

    def get_auth_status(self) -> Dict[str, Any]:
        """Returns OAuth configuration and authorization status."""
        client_config = self.get_client_config()
        cfg = client_config.get("web", client_config.get("installed", {}))
        client_id = cfg.get("client_id", "")
        
        has_client = bool(client_id and not client_id.startswith("traceguard-demo"))
        has_token = self.token_path.exists()
        user_email = None

        if has_token:
            try:
                with open(self.token_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    user_email = data.get("user_email")
            except Exception:
                pass

        return {
            "is_configured": has_client or has_token,
            "is_authorized": has_token,
            "client_id": client_id[:16] + "..." if client_id else None,
            "user_email": user_email or ("secops.monitoring@gmail.com" if has_token else None),
            "scopes": SCOPES,
            "redirect_uri": "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
        }

    def generate_xoauth2_string(self, username: str, access_token: str) -> str:
        """Generates XOAUTH2 string for IMAP/SMTP authentication."""
        auth_string = (
            f"user={username}\1auth=Bearer {access_token}\1\1".encode("utf-8")
        )
        return base64.b64encode(auth_string).decode("ascii")

    def get_gmail_service(self):
        """Constructs authenticated Gmail API service client."""
        creds = self.get_valid_credentials()
        if not creds:
            raise ValueError("Gmail OAuth credentials not found or expired. Please authorize first.")
        return build("gmail", "v1", credentials=creds)

    def fetch_raw_messages(self, max_results: int = 5) -> List[Tuple[str, bytes]]:
        """Fetches raw RFC 822 MIME bytes for recent messages via Gmail API."""
        service = self.get_gmail_service()
        results = service.users().messages().list(userId="me", maxResults=max_results).execute()
        messages = results.get("messages", [])

        raw_messages = []
        for msg_meta in messages:
            msg_id = msg_meta["id"]
            msg = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
            raw_bytes = base64.urlsafe_b64decode(msg["raw"].encode("utf-8"))
            raw_messages.append((msg_id, raw_bytes))

        return raw_messages

    def apply_quarantine(self, message_id: str) -> bool:
        """Applies TRACEGUARD_QUARANTINE label and removes INBOX label."""
        try:
            service = self.get_gmail_service()
            
            # Ensure label exists
            labels = service.users().labels().list(userId="me").execute().get("labels", [])
            quarantine_label_id = None
            for l in labels:
                if l["name"].upper() in ("TRACEGUARD_QUARANTINE", "TRACEGUARD/QUARANTINE"):
                    quarantine_label_id = l["id"]
                    break

            if not quarantine_label_id:
                new_label = service.users().labels().create(
                    userId="me",
                    body={
                        "name": "TRACEGUARD_QUARANTINE",
                        "labelListVisibility": "labelShow",
                        "messageListVisibility": "show"
                    }
                ).execute()
                quarantine_label_id = new_label["id"]

            # Modify message labels: remove INBOX, add quarantine label
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={
                    "addLabelIds": [quarantine_label_id],
                    "removeLabelIds": ["INBOX"]
                }
            ).execute()
            return True
        except Exception as e:
            logger.error(f"Failed to apply Gmail quarantine label: {e}")
            return False


gmail_oauth_manager = GmailOAuthManager()
