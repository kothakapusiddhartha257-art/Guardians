from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from backend.app.services.email_ingestion.gmail_oauth import gmail_oauth_manager
from backend.app.services.email_monitor import email_monitor

router = APIRouter(prefix="/oauth/gmail", tags=["Gmail OAuth 2.0"])


class ClientCredentialsRequest(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"


class OAuthExchangeRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None


class SyncRequest(BaseModel):
    limit: int = 20


@router.get("/status")
async def get_gmail_oauth_status():
    """
    Check current Google OAuth 2.0 configuration, authorization status,
    incremental sync state, and user email (Phase 7 Specification).
    """
    return gmail_oauth_manager.get_auth_status()


@router.post("/credentials")
async def save_gmail_credentials(req: ClientCredentialsRequest):
    """Save Google Cloud Console OAuth 2.0 Client ID and Secret."""
    config = {
        "web": {
            "client_id": req.client_id.strip(),
            "client_secret": req.client_secret.strip(),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [
                req.redirect_uri,
                "http://127.0.0.1:8000/api/v1/oauth/gmail/callback",
                "http://localhost:8000/api/v1/oauth/gmail/callback"
            ]
        }
    }
    gmail_oauth_manager.save_client_config(config)
    return {"status": "success", "message": "Google OAuth credentials saved successfully."}


@router.get("/auth-url")
async def get_google_auth_url(redirect_uri: Optional[str] = Query(None)):
    """Generate the Google OAuth 2.0 Consent Screen URL with PKCE / CSRF state."""
    red_uri = redirect_uri or "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
    try:
        auth_url, state = gmail_oauth_manager.get_authorization_url(red_uri)
        return {
            "auth_url": auth_url,
            "state": state,
            "redirect_uri": red_uri
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate Google auth URL: {str(e)}")


@router.post("/exchange")
async def exchange_google_oauth_code(req: OAuthExchangeRequest):
    """Exchanges Google authorization code for access token via backend without exposing client secret."""
    redirect_uri = req.redirect_uri or "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
    try:
        token_data = gmail_oauth_manager.exchange_code_for_token(req.code, redirect_uri)
        return {
            "status": "success",
            "access_token": token_data.get("token"),
            "expires_in": 3600,
            "user_email": token_data.get("user_email", "authenticated.user@gmail.com"),
            "scopes": token_data.get("scopes", [])
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {str(e)}")


@router.post("/refresh")
async def refresh_google_oauth_token():
    """Silently refreshes Google OAuth access token using server-persisted encrypted refresh token."""
    creds = gmail_oauth_manager.get_valid_credentials()
    if not creds or not creds.token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google authorization expired or revoked. Please reconnect."
        )
    return {
        "status": "success",
        "access_token": creds.token,
        "expires_in": 3600
    }


@router.get("/callback")
async def google_oauth_callback(
    code: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    state: Optional[str] = Query(None)
):
    """
    Handles OAuth 2.0 callback from Google, securely exchanges code for encrypted token,
    and redirects user back to TRACEGUARD with authenticated status.
    """
    if error:
        return RedirectResponse(url=f"http://127.0.0.1:5173/monitoring?oauth_error={error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from Google OAuth response")

    redirect_uri = "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
    try:
        token_data = gmail_oauth_manager.exchange_code_for_token(code, redirect_uri)
        user_email = token_data.get("user_email", "authenticated.user@gmail.com")

        # Automatically connect Gmail mailbox in EmailMonitor
        await email_monitor.connect_mailbox(
            provider_type="gmail",
            display_name=f"Gmail Gateway ({user_email})",
            credentials={"access_token": token_data.get("token")}
        )

        return RedirectResponse(url=f"http://127.0.0.1:5173/monitoring?gmail_connected=true&email={user_email}")
    except Exception as e:
        return RedirectResponse(url=f"http://127.0.0.1:5173/monitoring?oauth_error={str(e)}")


@router.post("/sync-now")
async def sync_gmail_inbox_now(req: SyncRequest = SyncRequest()):
    """
    Incrementally synchronizes Gmail messages using the History API,
    converts to byte-accurate RFC822, and ingests directly into the 11-stage Forensic DAG.
    """
    try:
        result = await gmail_oauth_manager.sync_inbox_incremental(limit=req.limit)
        return result
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except ConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS if "rate limit" in str(e).lower() else status.HTTP_502_BAD_GATEWAY,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Gmail incremental sync failed: {str(e)}"
        )


@router.get("/message/{message_id}")
async def get_single_message_analysis(message_id: str):
    """On-demand scan / lookup for a specific Gmail message ID (Phase 12)."""
    try:
        return await gmail_oauth_manager.get_or_scan_single_message(message_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to analyze Gmail message {message_id}: {str(e)}")


@router.post("/disconnect")
async def disconnect_google_account():
    """Revokes token with Google and cleans up stored encrypted credentials (Phase 6)."""
    return gmail_oauth_manager.revoke_and_disconnect()
