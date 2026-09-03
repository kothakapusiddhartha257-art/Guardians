import os
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.services.gmail_imap_service import gmail_imap_service, LATEST_SCAN_SUMMARY
from backend.app.services.pipeline import INVESTIGATION_CACHE

router = APIRouter(prefix="/gmail", tags=["Gmail IMAP"])


class ScanRequest(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)


class AutoScanRequest(BaseModel):
    enabled: bool = True
    interval_minutes: int = Field(default=5, ge=1, le=60)


@router.get("/status")
async def get_gmail_status():
    """Returns the configuration and connectivity status of the dedicated Gmail IMAP mailbox."""
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        try:
            from dotenv import dotenv_values
            env_vals = dotenv_values(".env")
            if env_vals.get("GMAIL_APP_PASSWORD"):
                settings.GMAIL_APP_PASSWORD = env_vals["GMAIL_APP_PASSWORD"]
            if env_vals.get("GMAIL_EMAIL"):
                settings.GMAIL_EMAIL = env_vals["GMAIL_EMAIL"]
        except Exception:
            pass

    is_conf = gmail_imap_service.is_configured()
    return {
        "email": settings.GMAIL_EMAIL,
        "configured": is_conf,
        "connected": gmail_imap_service.is_connected,
        "host": settings.IMAP_HOST,
        "port": settings.IMAP_PORT,
        "folder": settings.IMAP_FOLDER,
        "auto_scan_enabled": gmail_imap_service.auto_scan_enabled,
        "auto_scan_interval_minutes": gmail_imap_service.auto_scan_interval_minutes,
        "total_scanned_count": LATEST_SCAN_SUMMARY["total_scanned"],
        "last_summary": LATEST_SCAN_SUMMARY
    }


@router.post("/test-connection")
async def test_gmail_connection():
    """Tests the live IMAP SSL/TLS connection to Gmail with configured credentials."""
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        try:
            from dotenv import dotenv_values
            env_vals = dotenv_values(".env")
            if env_vals.get("GMAIL_APP_PASSWORD"):
                settings.GMAIL_APP_PASSWORD = env_vals["GMAIL_APP_PASSWORD"]
            if env_vals.get("GMAIL_EMAIL"):
                settings.GMAIL_EMAIL = env_vals["GMAIL_EMAIL"]
        except Exception:
            pass

    result = await gmail_imap_service.test_connection()
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("message", "Unable to authenticate with Gmail. Check the backend Gmail configuration.")
        )
    return result


@router.post("/scan")
async def scan_gmail_inbox(req: ScanRequest = ScanRequest()):
    """
    Retrieves latest emails from Gmail INBOX, preserves complete raw RFC822 bytes,
    deduplicates already scanned emails, runs the 11-step forensic DAG, and stores results.
    """
    try:
        scan_outcome = await gmail_imap_service.fetch_and_scan_emails(limit=req.limit)
        return scan_outcome
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Gmail scan failed: {str(e)}"
        )


@router.get("/results")
async def get_gmail_scanned_results():
    """Returns list of previously scanned Gmail emails with forensic scores and signals."""
    return {
        "mailbox": settings.GMAIL_EMAIL,
        "summary": LATEST_SCAN_SUMMARY,
        "results": gmail_imap_service.get_results()
    }


@router.get("/results/{email_id}")
async def get_gmail_email_result(email_id: str):
    """Retrieves full investigation bundle for a specific Gmail email."""
    if email_id in INVESTIGATION_CACHE:
        return INVESTIGATION_CACHE[email_id]

    rec = gmail_imap_service.get_result_by_id(email_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Email investigation not found.")
    return rec


@router.post("/auto-scan")
async def toggle_auto_scan(req: AutoScanRequest):
    """Configures the automatic periodic background scan loop."""
    if req.enabled:
        gmail_imap_service.start_auto_scan(interval_minutes=req.interval_minutes)
    else:
        gmail_imap_service.stop_auto_scan()

    return {
        "auto_scan_enabled": gmail_imap_service.auto_scan_enabled,
        "interval_minutes": gmail_imap_service.auto_scan_interval_minutes,
        "message": f"Auto-scan {'enabled' if req.enabled else 'disabled'}."
    }
