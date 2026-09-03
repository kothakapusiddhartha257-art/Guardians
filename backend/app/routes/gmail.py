"""Local, read-only Gmail OAuth and manual message scanning.

Tokens remain on this machine under data/oauth_credentials and are never
returned to the browser. This router deliberately does not label, delete, or
otherwise modify Gmail messages.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from app.routes.analyze import _analyze
from app.routes.frontend import _ui_bundle, store_investigation

# Google may return canonical/combined scope values. This merely accepts its
# granted read-only scope set; it does not request write access.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

router = APIRouter(prefix="/api/v1/oauth/gmail", tags=["Gmail (read-only)"])
logger = logging.getLogger(__name__)
OAUTH_DIR = Path(__file__).resolve().parents[2] / "data" / "oauth_credentials"
TOKEN_FILE = OAUTH_DIR / "token.json"
REDIRECT_URI = "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/userinfo.email"]
_states: set[str] = set()
_pending_flows: dict[str, Flow] = {}


def _client_file() -> Path:
    candidates = list(OAUTH_DIR.glob("client_secret*.json")) + list(OAUTH_DIR.glob("credentials.json"))
    if not candidates:
        raise HTTPException(400, "OAuth client JSON is missing from data/oauth_credentials.")
    return candidates[0]


def _flow() -> Flow:
    return Flow.from_client_secrets_file(str(_client_file()), scopes=SCOPES, redirect_uri=REDIRECT_URI)


def _credentials() -> Credentials:
    if not TOKEN_FILE.exists():
        raise HTTPException(401, "Gmail is not authorized yet.")
    data = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
    creds = Credentials.from_authorized_user_info(data, SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
    if not creds.valid:
        raise HTTPException(401, "Gmail authorization expired; connect Gmail again.")
    return creds


def _account_email() -> str | None:
    """Return the address of the mailbox that granted the read-only token."""
    credentials = _credentials()
    try:
        # Gmail's profile endpoint is the most direct source for the connected
        # mailbox address and works with gmail.readonly alone.
        gmail = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        return gmail.users().getProfile(userId="me").execute().get("emailAddress")
    except Exception:
        try:
            oauth = build("oauth2", "v2", credentials=credentials, cache_discovery=False)
            return oauth.userinfo().get().execute().get("email")
        except Exception:
            return None


@router.get("/status")
def status() -> dict:
    configured = bool(list(OAUTH_DIR.glob("client_secret*.json")) or (OAUTH_DIR / "credentials.json").exists())
    user_email = None
    if TOKEN_FILE.exists():
        try:
            user_email = _account_email()
        except Exception:
            pass
    return {"is_configured": configured, "is_authorized": TOKEN_FILE.exists(), "user_email": user_email,
            "mode": "read-only", "redirect_uri": REDIRECT_URI}


@router.get("/auth-url")
def auth_url() -> dict:
    flow = _flow()
    url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopes="true")
    _states.add(state)
    _pending_flows[state] = flow
    return {"auth_url": url, "redirect_uri": REDIRECT_URI}


@router.get("/connect")
def connect() -> RedirectResponse:
    """Browser-friendly entry point for the local Gmail authorization flow."""
    flow = _flow()
    url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopes="true")
    _states.add(state)
    _pending_flows[state] = flow
    return RedirectResponse(url)


@router.get("/callback")
def callback(code: str | None = Query(None), state: str | None = Query(None), error: str | None = Query(None)):
    if error:
        return RedirectResponse(f"http://127.0.0.1:5173/monitoring?oauth_error={error}")
    if not code or not state or state not in _states:
        return RedirectResponse("http://127.0.0.1:5173/monitoring?oauth_error=invalid_state")
    _states.discard(state)
    try:
        # Reusing the original Flow retains its PKCE code verifier. Recreating
        # it here causes Google's token endpoint to reject the grant.
        flow = _pending_flows.pop(state, None)
        if flow is None:
            raise ValueError("OAuth session expired; start the Gmail connection again.")
        flow.fetch_token(code=code)
        TOKEN_FILE.write_text(flow.credentials.to_json(), encoding="utf-8")
        return RedirectResponse("http://127.0.0.1:5173/monitoring?gmail_connected=true")
    except Exception as exc:
        # Do not disclose authorization codes or token material in the URL.
        logger.exception("Gmail OAuth callback failed")
        return RedirectResponse(f"http://127.0.0.1:5173/login?oauth_error={type(exc).__name__}")


@router.post("/sync-now")
def sync_now(limit: int = Query(10, ge=1, le=25)) -> dict:
    service = build("gmail", "v1", credentials=_credentials(), cache_discovery=False)
    message_refs = service.users().messages().list(userId="me", maxResults=limit).execute().get("messages", [])
    results = []
    for item in message_refs:
        gmail_id = item["id"]
        message = service.users().messages().get(userId="me", id=gmail_id, format="raw").execute()
        raw = base64.urlsafe_b64decode(message["raw"] + "===")
        analysis = _analyze(raw).model_dump()
        email_id = uuid4().hex
        bundle = _ui_bundle(email_id, raw, analysis)
        store_investigation(email_id, bundle)
        results.append({"email_id": email_id, "gmail_message_id": gmail_id,
                        "subject": bundle["email"]["headers_normalized"].get("subject"),
                        "from_address": bundle["email"]["headers_normalized"]["from_address"].get("address"),
                        "threat_score": bundle["risk_score"]["threat_score"],
                        "classification": bundle["risk_score"]["classification"]})
    return {"status": "success", "mode": "read-only", "messages_scanned": len(results), "results": results}
