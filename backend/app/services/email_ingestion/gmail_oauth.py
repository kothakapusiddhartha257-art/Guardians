import os
import json
import base64
import logging
import asyncio
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from cryptography.fernet import Fernet
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError
import requests

from backend.app.core.config import BASE_DIR, settings
from backend.app.services.pipeline import execute_analysis_dag, INVESTIGATION_CACHE

logger = logging.getLogger(__name__)

OAUTH_DIR = BASE_DIR / "data" / "oauth_credentials"
OAUTH_DIR.mkdir(parents=True, exist_ok=True)

CREDENTIALS_FILE = OAUTH_DIR / "credentials.json"
TOKEN_ENC_FILE = OAUTH_DIR / "token.enc"
TOKEN_FILE_LEGACY = OAUTH_DIR / "token.json"

# Minimal viable scope for forensic security scanning (Phase 0 Scope Lock)
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email"
]

# Deduplication registry mapping gmail_message_id -> forensic case summary
# Prevents duplicate case creation under concurrent sync or resyncs (Phase 9)
PROCESSED_GMAIL_IDS: Dict[str, Dict[str, Any]] = {}

# In-memory sync summary counters
OAUTH_SYNC_SUMMARY: Dict[str, Any] = {
    "total_ingested": 0,
    "quarantined": 0,
    "suspicious": 0,
    "clean": 0,
    "duplicates_skipped": 0,
    "last_synced_at": None
}


def _derive_fernet_key(secret: str) -> bytes:
    """Derives a secure 32-byte URL-safe base64 key from application SECRET_KEY."""
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class GmailOAuthManager:
    """
    Production-grade Google OAuth 2.0 and Gmail API Synchronization Manager.
    
    Adheres strictly to the TRACEGUARD Master Implementation Plan:
    1. Encrypted token storage at rest (Fernet) — tokens never touch browser/client.
    2. Minimum viable scope (gmail.readonly).
    3. Incremental synchronization via History API (avoids full-mailbox downloads).
    4. Concurrency protection via asyncio.Lock to eliminate race conditions.
    5. Feeds byte-accurate RFC822 directly into the existing forensic DAG (no parallel scorers).
    6. Graceful token revocation and rate-limit backoff handling.
    """

    def __init__(
        self,
        credentials_path: Path = CREDENTIALS_FILE,
        token_enc_path: Path = TOKEN_ENC_FILE
    ):
        self.credentials_path = credentials_path
        self.token_enc_path = token_enc_path
        self._sync_lock = asyncio.Lock()
        self._fernet = Fernet(_derive_fernet_key(settings.SECRET_KEY))

        # Runtime synchronization state
        self.sync_state: str = "idle"  # idle | syncing | error | needs_reauth
        self.last_history_id: Optional[str] = None
        self.last_synced_at: Optional[str] = None
        self.user_email: Optional[str] = None
        self.active_states: Dict[str, float] = {}  # state -> timestamp for CSRF validation

        # Migrate legacy unencrypted token if exists
        self._migrate_legacy_token()

    def _migrate_legacy_token(self):
        """Encrypts legacy plain token.json if found and removes the unencrypted file."""
        try:
            if TOKEN_FILE_LEGACY.exists() and not self.token_enc_path.exists():
                with open(TOKEN_FILE_LEGACY, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.save_encrypted_token(data)
                TOKEN_FILE_LEGACY.unlink(missing_ok=True)
                logger.info("[OAuth Security] Legacy token migrated to AES/Fernet encryption at rest.")
        except Exception as e:
            logger.warning(f"[OAuth Security] Token migration notice: {e}")

    def save_encrypted_token(self, token_data: Dict[str, Any]) -> None:
        """Encrypts token payload with Fernet before persisting to disk."""
        raw_json = json.dumps(token_data).encode("utf-8")
        encrypted = self._fernet.encrypt(raw_json)
        with open(self.token_enc_path, "wb") as f:
            f.write(encrypted)
        self.user_email = token_data.get("user_email")

    def load_encrypted_token(self) -> Optional[Dict[str, Any]]:
        """Decrypts token payload from disk."""
        if not self.token_enc_path.exists():
            return None
        try:
            with open(self.token_enc_path, "rb") as f:
                encrypted = f.read()
            decrypted = self._fernet.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            logger.error(f"[OAuth Security] Failed to decrypt token file: {e}")
            return None

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

        return {
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
                    "http://127.0.0.1:5173/monitoring"
                ]
            }
        }

    def get_authorization_url(self, redirect_uri: str) -> Tuple[str, str]:
        """Generates Google OAuth 2.0 authorization URL with CSRF state token."""
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
        self.active_states[state] = time.time()
        return auth_url, state

    def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchanges authorization code for access and refresh tokens, encrypted at rest."""
        client_config = self.get_client_config()
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        flow.fetch_token(code=code)
        creds = flow.credentials

        user_email = "authenticated.user@gmail.com"
        try:
            oauth2_service = build("oauth2", "v2", credentials=creds)
            user_info = oauth2_service.userinfo().get().execute()
            user_email = user_info.get("email", user_email)
        except Exception as e:
            logger.warning(f"[OAuth] Could not fetch userinfo email: {e}")

        token_data = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
            "user_email": user_email,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        self.save_encrypted_token(token_data)
        self.user_email = user_email
        self.sync_state = "idle"
        return token_data

    def get_valid_credentials(self) -> Optional[Credentials]:
        """Retrieves and silently refreshes credentials. Handles revocation gracefully."""
        token_data = self.load_encrypted_token()
        if not token_data:
            return None

        try:
            creds = Credentials(
                token=token_data.get("token"),
                refresh_token=token_data.get("refresh_token"),
                token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=token_data.get("client_id"),
                client_secret=token_data.get("client_secret"),
                scopes=token_data.get("scopes", SCOPES)
            )

            # Lazy refresh on use
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    token_data["token"] = creds.token
                    self.save_encrypted_token(token_data)
                    logger.info("[OAuth] Successfully refreshed short-lived Google access token.")
                except RefreshError as e:
                    logger.error(f"[OAuth] Google token refresh failed (likely revoked by user): {e}")
                    self.sync_state = "needs_reauth"
                    return None

            self.user_email = token_data.get("user_email")
            return creds
        except Exception as e:
            logger.error(f"[OAuth] Error validating credentials: {e}")
            self.sync_state = "needs_reauth"
            return None

    def get_gmail_service(self):
        """Builds authenticated Gmail API service."""
        creds = self.get_valid_credentials()
        if not creds:
            raise PermissionError("Google Gmail authorization expired or missing. Please reconnect your account.")
        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    def revoke_and_disconnect(self) -> Dict[str, Any]:
        """Calls Google token revocation endpoint and securely removes local encrypted tokens."""
        token_data = self.load_encrypted_token()
        revoked_from_google = False

        if token_data and token_data.get("token"):
            try:
                res = requests.post(
                    "https://oauth2.googleapis.com/revoke",
                    params={"token": token_data["token"]},
                    headers={"content-type": "application/x-www-form-urlencoded"},
                    timeout=5
                )
                revoked_from_google = res.status_code == 200
            except Exception as e:
                logger.warning(f"[OAuth Disconnect] Google revoke call notice: {e}")

        # Remove local encrypted credentials
        self.token_enc_path.unlink(missing_ok=True)
        TOKEN_FILE_LEGACY.unlink(missing_ok=True)
        self.user_email = None
        self.sync_state = "idle"
        self.last_history_id = None

        return {
            "status": "disconnected",
            "revoked_from_google": revoked_from_google,
            "message": "Google account successfully disconnected and local tokens deleted."
        }

    async def sync_inbox_incremental(
        self,
        limit: int = 20,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Incrementally synchronizes Gmail messages using the History API.
        """
        async with self._sync_lock:
            self.sync_state = "syncing"
            try:
                service = self.get_gmail_service()
            except PermissionError as e:
                self.sync_state = "needs_reauth"
                raise e

            message_ids_to_fetch: List[str] = []

            # 1. Fetch incremental delta or initial mailbox list
            try:
                if self.last_history_id:
                    try:
                        hist_res = service.users().history().list(
                            userId="me",
                            startHistoryId=self.last_history_id,
                            maxResults=limit
                        ).execute()

                        hist_records = hist_res.get("history", [])
                        for h in hist_records:
                            for msg_added in h.get("messagesAdded", []):
                                mid = msg_added.get("message", {}).get("id")
                                if mid and mid not in message_ids_to_fetch:
                                    message_ids_to_fetch.append(mid)

                        self.last_history_id = hist_res.get("historyId", self.last_history_id)
                        logger.info(f"[History API] Found {len(message_ids_to_fetch)} new messages via historyId {self.last_history_id}")
                    except HttpError as e:
                        if e.resp.status in (404, 400):
                            logger.info("[History API] Stale historyId (>7 days). Falling back to standard listing.")
                            self.last_history_id = None
                        elif e.resp.status == 429:
                            await asyncio.sleep(2)
                            raise e
                        else:
                            raise e

                # Fallback / Initial Full List
                if not self.last_history_id or not message_ids_to_fetch:
                    list_res = service.users().messages().list(
                        userId="me",
                        maxResults=min(limit, 20)
                    ).execute()
                    message_ids_to_fetch = [m["id"] for m in list_res.get("messages", [])]
                    
                    try:
                        profile = service.users().getProfile(userId="me").execute()
                        self.last_history_id = profile.get("historyId")
                    except Exception:
                        pass

            except HttpError as e:
                self.sync_state = "error"
                if e.resp.status == 429:
                    raise ConnectionError("Gmail API rate limit exceeded. Backing off.")
                raise ConnectionError(f"Gmail API error: {e}")

            # 2. Process message IDs through the existing forensic DAG
            processed_results = []
            new_count = 0
            dup_count = 0

            for idx, msg_id in enumerate(message_ids_to_fetch):
                # Deduplication check (Phase 9)
                if msg_id in PROCESSED_GMAIL_IDS:
                    dup_count += 1
                    processed_results.append(PROCESSED_GMAIL_IDS[msg_id])
                    OAUTH_SYNC_SUMMARY["duplicates_skipped"] += 1
                    continue

                # Fetch raw RFC822 MIME bytes with quota backoff retry
                raw_bytes = None
                for attempt in range(3):
                    try:
                        msg_obj = service.users().messages().get(
                            userId="me",
                            id=msg_id,
                            format="raw"
                        ).execute()
                        raw_bytes = base64.urlsafe_b64decode(msg_obj["raw"].encode("utf-8"))
                        break
                    except HttpError as e:
                        if e.resp.status == 429:
                            await asyncio.sleep(1.5 * (attempt + 1))
                        else:
                            break
                    except Exception:
                        break

                if not raw_bytes:
                    continue

                # Ingest into EXISTING 11-stage Forensic DAG (Phase 10 Golden Rule)
                try:
                    bundle = await execute_analysis_dag(raw_bytes)
                    score = bundle.risk_score.threat_score
                    classification = bundle.risk_score.classification

                    if score >= 0.75:
                        OAUTH_SYNC_SUMMARY["quarantined"] += 1
                    elif score >= 0.35:
                        OAUTH_SYNC_SUMMARY["suspicious"] += 1
                    else:
                        OAUTH_SYNC_SUMMARY["clean"] += 1

                    OAUTH_SYNC_SUMMARY["total_ingested"] += 1
                    new_count += 1

                    summary_entry = {
                        "gmail_message_id": msg_id,
                        "email_id": bundle.email.email_id,
                        "case_id": bundle.case_id,
                        "report_id": bundle.report_id,
                        "subject": bundle.email.headers_normalized.subject or "No Subject",
                        "from_address": bundle.email.headers_normalized.from_address.address if bundle.email.headers_normalized.from_address else "Unknown",
                        "threat_score": score,
                        "classification": classification,
                        "investigation_url": f"/investigation?id={bundle.report_id or bundle.email.email_id}",
                        "scanned_at": datetime.now(timezone.utc).isoformat()
                    }
                    PROCESSED_GMAIL_IDS[msg_id] = summary_entry
                    processed_results.append(summary_entry)

                    from backend.app.services.email_monitor import email_monitor
                    await email_monitor.broadcast_websocket_event({
                        "event_type": "GMAIL_OAUTH_EMAIL_INGESTED",
                        "data": summary_entry
                    })

                    if progress_callback:
                        progress_callback(idx + 1, len(message_ids_to_fetch), summary_entry["subject"], score)

                except Exception as e:
                    logger.error(f"[Forensic DAG Ingest Error] Failed to score Gmail message {msg_id}: {e}")

            now_iso = datetime.now(timezone.utc).isoformat()
            self.last_synced_at = now_iso
            OAUTH_SYNC_SUMMARY["last_synced_at"] = now_iso
            self.sync_state = "idle"

            return {
                "status": "success",
                "synced_count": len(processed_results),
                "new_messages_analyzed": new_count,
                "duplicates_skipped": dup_count,
                "summary": OAUTH_SYNC_SUMMARY,
                "results": processed_results
            }

    async def get_or_scan_single_message(self, message_id: str) -> Dict[str, Any]:
        """On-demand scan for a single Gmail message ID (Phase 12)."""
        if message_id in PROCESSED_GMAIL_IDS:
            return PROCESSED_GMAIL_IDS[message_id]

        service = self.get_gmail_service()
        msg_obj = service.users().messages().get(
            userId="me",
            id=message_id,
            format="raw"
        ).execute()

        raw_bytes = base64.urlsafe_b64decode(msg_obj["raw"].encode("utf-8"))
        bundle = await execute_analysis_dag(raw_bytes)

        summary_entry = {
            "gmail_message_id": message_id,
            "email_id": bundle.email.email_id,
            "case_id": bundle.case_id,
            "report_id": bundle.report_id,
            "subject": bundle.email.headers_normalized.subject or "No Subject",
            "from_address": bundle.email.headers_normalized.from_address.address if bundle.email.headers_normalized.from_address else "Unknown",
            "threat_score": bundle.risk_score.threat_score,
            "classification": bundle.risk_score.classification,
            "investigation_url": f"/investigation?id={bundle.report_id or bundle.email.email_id}",
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }
        PROCESSED_GMAIL_IDS[message_id] = summary_entry
        return summary_entry

    def get_auth_status(self) -> Dict[str, Any]:
        """Returns comprehensive status conforming to Phase 7 specification."""
        client_config = self.get_client_config()
        cfg = client_config.get("web", client_config.get("installed", {}))
        client_id = cfg.get("client_id", "")
        has_client = bool(client_id and not client_id.startswith("traceguard-demo"))
        has_token = self.token_enc_path.exists()

        email = self.user_email
        if has_token and not email:
            token_data = self.load_encrypted_token()
            if token_data:
                email = token_data.get("user_email")
                self.user_email = email

        return {
            "is_configured": has_client or has_token,
            "is_authorized": has_token and self.sync_state != "needs_reauth",
            "client_id": client_id[:16] + "..." if client_id else None,
            "user_email": email or ("secops.monitoring@gmail.com" if has_token else None),
            "scopes": SCOPES,
            "scopes_granted": SCOPES,
            "sync_state": self.sync_state,
            "last_synced_at": self.last_synced_at or OAUTH_SYNC_SUMMARY["last_synced_at"],
            "total_synced": OAUTH_SYNC_SUMMARY["total_ingested"],
            "summary": OAUTH_SYNC_SUMMARY,
            "redirect_uri": "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
        }

    def generate_xoauth2_string(self, username: str, access_token: str) -> str:
        auth_string = f"user={username}\1auth=Bearer {access_token}\1\1".encode("utf-8")
        return base64.b64encode(auth_string).decode("ascii")


gmail_oauth_manager = GmailOAuthManager()
