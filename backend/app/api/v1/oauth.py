from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
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


@router.get("/status")
async def get_gmail_oauth_status():
    """Check current Google OAuth 2.0 configuration, authorization status, and authorized email."""
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
    """Generate the Google OAuth 2.0 Consent Screen URL for the user to authorize Gmail access."""
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
    """Exchanges Google authorization code for access token via backend without exposing client secret in client extensions."""
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
    """Silently refreshes Google OAuth access token using server-persisted refresh token."""
    creds = gmail_oauth_manager.get_valid_credentials()
    if not creds or not creds.token:
        raise HTTPException(status_code=401, detail="No valid refresh token or authorization found.")
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
    """Handles OAuth 2.0 callback from Google, exchanges authorization code for tokens, and connects mailbox."""
    if error:
        return RedirectResponse(url=f"http://127.0.0.1:5173/monitoring?oauth_error={error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from Google OAuth response")

    redirect_uri = "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
    try:
        token_data = gmail_oauth_manager.exchange_code_for_token(code, redirect_uri)
        user_email = token_data.get("user_email", "corporate@gmail.com")

        # Automatically connect Gmail mailbox in EmailMonitor
        conn_id = "mailbox-gmail-oauth"
        await email_monitor.connect_mailbox(
            provider_type="gmail",
            display_name=f"Gmail Gateway ({user_email})",
            credentials={"access_token": token_data.get("token")}
        )

        return RedirectResponse(url=f"http://127.0.0.1:5173/monitoring?gmail_connected=true&email={user_email}")
    except Exception as e:
        return RedirectResponse(url=f"http://127.0.0.1:5173/monitoring?oauth_error={str(e)}")


@router.post("/sync-now")
async def sync_gmail_inbox_now():
    """Fetch unread/recent raw emails from authorized Gmail inbox into the TRACEGUARD DAG pipeline."""
    # Find Gmail provider in email_monitor
    gmail_provider = None
    for p in email_monitor.providers.values():
        if hasattr(p, "sync_live_inbox"):
            gmail_provider = p
            break

    if not gmail_provider:
        from backend.app.services.email_ingestion.gmail import GmailProvider
        gmail_provider = GmailProvider("Gmail Gateway")
        gmail_provider.on_new_message_callback = email_monitor.handle_incoming_raw_message

    try:
        count = await gmail_provider.sync_live_inbox()
        return {
            "status": "success",
            "messages_ingested": count,
            "message": f"Successfully ingested {count} emails from Gmail into TRACEGUARD pipeline"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Gmail sync failed: {str(e)}")
