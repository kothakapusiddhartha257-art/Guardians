import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.services.email_ingestion.gmail_oauth import gmail_oauth_manager
from backend.app.services.email_monitor import email_monitor

router = APIRouter(prefix="/auth", tags=["User Authentication & Session"])

# Global session and connected mailbox state
CURRENT_USER_SESSION: Dict[str, Any] = {
    "is_authenticated": False,
    "user_email": None,
    "auth_provider": None,  # google | microsoft | imap | demo
    "role": "SecOps Lead Analyst",
    "authenticated_at": None
}

CONNECTED_MAILBOXES: Dict[str, Dict[str, Any]] = {}
ACTIVE_MAILBOX_ID: Optional[str] = None


class DemoLaunchRequest(BaseModel):
    scenario: str = "bec_wire_transfer"  # bec_wire_transfer | credential_harvesting | malware_executable | clean_newsletter


class SelectMailboxRequest(BaseModel):
    mailbox_id: str


@router.get("/session")
async def get_current_session():
    """Returns the current TRACEGUARD user authentication state and connected mailboxes."""
    global CURRENT_USER_SESSION, ACTIVE_MAILBOX_ID

    # Sync with Gmail OAuth manager if authorized
    oauth_status = gmail_oauth_manager.get_auth_status()
    if oauth_status["is_authorized"] and oauth_status.get("user_email"):
        gmail_mb_id = "mb-google-primary"
        if gmail_mb_id not in CONNECTED_MAILBOXES:
            CONNECTED_MAILBOXES[gmail_mb_id] = {
                "id": gmail_mb_id,
                "provider": "gmail",
                "email": oauth_status["user_email"],
                "display_name": f"Google Workspace ({oauth_status['user_email']})",
                "status": "CONNECTED",
                "last_synced_at": oauth_status.get("last_synced_at"),
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        else:
            CONNECTED_MAILBOXES[gmail_mb_id]["last_synced_at"] = oauth_status.get("last_synced_at")

        if not CURRENT_USER_SESSION["is_authenticated"]:
            CURRENT_USER_SESSION["is_authenticated"] = True
            CURRENT_USER_SESSION["user_email"] = oauth_status["user_email"]
            CURRENT_USER_SESSION["auth_provider"] = "google"
            CURRENT_USER_SESSION["authenticated_at"] = datetime.now(timezone.utc).isoformat()
            if not ACTIVE_MAILBOX_ID:
                ACTIVE_MAILBOX_ID = gmail_mb_id

    mailboxes_list = list(CONNECTED_MAILBOXES.values())
    active_mailbox = CONNECTED_MAILBOXES.get(ACTIVE_MAILBOX_ID) if ACTIVE_MAILBOX_ID else (mailboxes_list[0] if mailboxes_list else None)

    return {
        "authenticated": CURRENT_USER_SESSION["is_authenticated"],
        "user": {
            "email": CURRENT_USER_SESSION["user_email"],
            "provider": CURRENT_USER_SESSION["auth_provider"],
            "role": CURRENT_USER_SESSION["role"],
            "authenticated_at": CURRENT_USER_SESSION["authenticated_at"]
        } if CURRENT_USER_SESSION["is_authenticated"] else None,
        "active_mailbox": active_mailbox,
        "connected_mailboxes": mailboxes_list,
        "total_connected": len(mailboxes_list)
    }


@router.post("/demo")
async def launch_demo_session(req: DemoLaunchRequest):
    """
    Activates a zero-credential demo session with seeded scenarios (BEC, Phishing, Malware, Clean).
    No Google or IMAP credentials required.
    """
    global CURRENT_USER_SESSION, ACTIVE_MAILBOX_ID

    demo_mb_id = f"mb-demo-{uuid.uuid4().hex[:6]}"
    scenario_titles = {
        "bec_wire_transfer": "BEC Wire Transfer Fraud (Executive Spoof)",
        "credential_harvesting": "Microsoft 365 Credential Phish (Zero-Point)",
        "malware_executable": "Invoice Masqueraded Binary Malware",
        "clean_newsletter": "Clean Security Advisory Bulletin"
    }

    title = scenario_titles.get(req.scenario, "TRACEGUARD Seeded Threat Scenario")
    demo_email = "demo.analyst@traceguard.sec"

    # Register Demo Mailbox
    CONNECTED_MAILBOXES[demo_mb_id] = {
        "id": demo_mb_id,
        "provider": "demo",
        "email": demo_email,
        "display_name": f"Demo Environment ({title})",
        "status": "CONNECTED",
        "last_synced_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    ACTIVE_MAILBOX_ID = demo_mb_id
    CURRENT_USER_SESSION["is_authenticated"] = True
    CURRENT_USER_SESSION["user_email"] = demo_email
    CURRENT_USER_SESSION["auth_provider"] = "demo"
    CURRENT_USER_SESSION["authenticated_at"] = datetime.now(timezone.utc).isoformat()

    # Trigger simulator for chosen scenario in email_monitor
    try:
        from backend.app.services.email_ingestion.simulator import SimulatorProvider
        sim = SimulatorProvider("Demo Feed")
        await sim.simulate_inbound(scenario=req.scenario)
    except Exception as e:
        pass

    return {
        "status": "success",
        "message": f"Demo environment activated with scenario: {title}",
        "mailbox_id": demo_mb_id,
        "email": demo_email,
        "scenario": req.scenario
    }


@router.post("/logout")
async def logout_user_session():
    """Clears the user session and resets active mailbox."""
    global CURRENT_USER_SESSION, ACTIVE_MAILBOX_ID
    CURRENT_USER_SESSION["is_authenticated"] = False
    CURRENT_USER_SESSION["user_email"] = None
    CURRENT_USER_SESSION["auth_provider"] = None
    CURRENT_USER_SESSION["authenticated_at"] = None
    ACTIVE_MAILBOX_ID = None

    return {
        "status": "success",
        "message": "Logged out successfully."
    }


@router.post("/mailboxes/select")
async def select_active_mailbox(req: SelectMailboxRequest):
    """Switches the active mailbox for the current user."""
    global ACTIVE_MAILBOX_ID
    if req.mailbox_id not in CONNECTED_MAILBOXES:
        raise HTTPException(status_code=404, detail="Mailbox not found in connected mailboxes list")

    ACTIVE_MAILBOX_ID = req.mailbox_id
    return {
        "status": "success",
        "active_mailbox": CONNECTED_MAILBOXES[ACTIVE_MAILBOX_ID]
    }


@router.delete("/mailboxes/{mailbox_id}")
async def disconnect_mailbox(mailbox_id: str):
    """Disconnects a specific mailbox."""
    global ACTIVE_MAILBOX_ID
    if mailbox_id in CONNECTED_MAILBOXES:
        mb = CONNECTED_MAILBOXES.pop(mailbox_id)
        if mb["provider"] == "gmail":
            gmail_oauth_manager.revoke_and_disconnect()

        if ACTIVE_MAILBOX_ID == mailbox_id:
            ACTIVE_MAILBOX_ID = next(iter(CONNECTED_MAILBOXES.keys()), None)
            if not ACTIVE_MAILBOX_ID:
                CURRENT_USER_SESSION["is_authenticated"] = False

        return {"status": "success", "message": f"Mailbox {mb['display_name']} disconnected."}

    raise HTTPException(status_code=404, detail="Mailbox not found")
