import pytest
from unittest.mock import MagicMock, patch
from starlette.testclient import TestClient

from backend.main import app
from backend.app.core.config import settings
from backend.app.services.gmail_imap_service import gmail_imap_service, SCANNED_GMAIL_REGISTRY

SAMPLE_IMAP_RFC822 = b"""From: Vendor Payments <billing@suspicious-wire-transfer.xyz>
To: kingkmn786@gmail.com
Subject: URGENT: Wire Transfer Routing Directive Update
Date: Thu, 03 Sep 2026 06:00:00 +0000
Message-ID: <test-imap-001@suspicious-wire-transfer.xyz>
Content-Type: text/plain; charset=utf-8

Dear Partner,
Please find attached updated banking details. Wire the invoice payment immediately to avoid shipment hold.
Routing: 021000021
Account: 9876543210
"""


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_gmail_imap_status_endpoint(client):
    res = client.get("/api/v1/gmail/status")
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "kingkmn786@gmail.com"
    assert "configured" in data
    assert "auto_scan_enabled" in data

    # Test alias route /api/gmail/status
    res_alias = client.get("/api/gmail/status")
    assert res_alias.status_code == 200
    assert res_alias.json()["email"] == "kingkmn786@gmail.com"


def test_gmail_imap_test_connection_unconfigured(client):
    with patch.object(settings, "GMAIL_APP_PASSWORD", ""):
        res = client.post("/api/v1/gmail/test-connection")
        # When unconfigured, should return 400 Bad Request with informative message
        assert res.status_code == 400
        assert "not configured" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_gmail_imap_fetch_and_deduplicate():
    # Mock IMAP4_SSL client returning 1 message
    mock_imap = MagicMock()
    mock_imap.search.return_value = ("OK", [b"101"])
    mock_imap.fetch.return_value = ("OK", [(b"101 (BODY.PEEK[] {123}", SAMPLE_IMAP_RFC822), b")"])

    with patch.object(settings, "GMAIL_APP_PASSWORD", "mock_valid_pass_1234"), \
         patch("imaplib.IMAP4_SSL", return_value=mock_imap):
        
        # 1. Run First Scan
        outcome = await gmail_imap_service.fetch_and_scan_emails(limit=5)
        assert outcome["status"] == "COMPLETE"
        assert len(outcome["results"]) == 1

        rec = outcome["results"][0]
        assert rec["subject"] == "URGENT: Wire Transfer Routing Directive Update"
        assert rec["threat_score"] > 0.35  # Suspicious/Malicious BEC directive
        assert "investigation_url" in rec
        assert rec["case_id"].startswith("CASE-")
        first_case_id = rec["case_id"]

        # 2. Run Second Scan -> Should Deduplicate & Return Same Investigation
        outcome2 = await gmail_imap_service.fetch_and_scan_emails(limit=5)
        assert outcome2["status"] == "COMPLETE"
        assert len(outcome2["results"]) == 1
        assert outcome2["results"][0]["case_id"] == first_case_id


def test_gmail_imap_scan_api_endpoint(client):
    mock_imap = MagicMock()
    mock_imap.search.return_value = ("OK", [b"202"])
    mock_imap.fetch.return_value = ("OK", [(b"202 (BODY.PEEK[] {123}", SAMPLE_IMAP_RFC822), b")"])

    with patch.object(settings, "GMAIL_APP_PASSWORD", "mock_valid_pass_1234"), \
         patch("imaplib.IMAP4_SSL", return_value=mock_imap):
        
        res = client.post("/api/v1/gmail/scan", json={"limit": 10})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "COMPLETE"
        assert "summary" in data
        assert len(data["results"]) >= 1


def test_gmail_auto_scan_toggle(client):
    res = client.post("/api/v1/gmail/auto-scan", json={"enabled": True, "interval_minutes": 10})
    assert res.status_code == 200
    assert res.json()["auto_scan_enabled"] is True
    assert res.json()["interval_minutes"] == 10

    res_off = client.post("/api/v1/gmail/auto-scan", json={"enabled": False, "interval_minutes": 5})
    assert res_off.status_code == 200
    assert res_off.json()["auto_scan_enabled"] is False
