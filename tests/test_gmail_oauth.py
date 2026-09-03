import pytest
import json
import base64
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

from backend.main import app
from backend.app.services.email_ingestion.gmail_oauth import (
    gmail_oauth_manager,
    PROCESSED_GMAIL_IDS,
    OAUTH_SYNC_SUMMARY
)

SAMPLE_RAW_RFC822 = b"""From: alerts@paypal-security-update.xyz
To: executive@corp.internal
Subject: URGENT: Wire Transfer Authorization Required
Date: Thu, 03 Sep 2026 12:00:00 +0000
Message-ID: <test-oauth-rfc822-001@paypal.xyz>
Authentication-Results: mx.google.com; dkim=fail; dmarc=fail

Please authorize the wire transfer of $50,000 immediately to account 987654321.
"""


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_gmail_oauth_status_endpoint(client):
    res = client.get("/api/v1/oauth/gmail/status")
    assert res.status_code == 200
    data = res.json()
    assert "is_configured" in data
    assert "scopes" in data
    assert "sync_state" in data
    assert "scopes_granted" in data


def test_gmail_oauth_credentials_save(client):
    res = client.post("/api/v1/oauth/gmail/credentials", json={
        "client_id": "test-client-12345.apps.googleusercontent.com",
        "client_secret": "test_mock_secret_key_12345",
        "redirect_uri": "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
    })
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    status_res = client.get("/api/v1/oauth/gmail/status")
    assert status_res.status_code == 200
    assert status_res.json()["is_configured"] is True


def test_gmail_oauth_auth_url_generation(client):
    res = client.get("/api/v1/oauth/gmail/auth-url")
    assert res.status_code == 200
    data = res.json()
    assert "auth_url" in data
    assert "state" in data
    assert "accounts.google.com" in data["auth_url"]


def test_fernet_token_encryption_at_rest():
    test_token_data = {
        "token": "ya29.test_token_secret_123",
        "refresh_token": "1//test_refresh_token_secret_456",
        "user_email": "security.analyst@company.com"
    }

    # Save encrypted
    gmail_oauth_manager.save_encrypted_token(test_token_data)

    # Verify that the file on disk is NOT plaintext JSON
    assert gmail_oauth_manager.token_enc_path.exists()
    with open(gmail_oauth_manager.token_enc_path, "rb") as f:
        raw_disk_bytes = f.read()
    assert b"ya29.test_token_secret_123" not in raw_disk_bytes
    assert b"1//test_refresh_token_secret_456" not in raw_disk_bytes

    # Verify decryption loads back original secrets
    decrypted = gmail_oauth_manager.load_encrypted_token()
    assert decrypted["token"] == test_token_data["token"]
    assert decrypted["refresh_token"] == test_token_data["refresh_token"]
    assert decrypted["user_email"] == test_token_data["user_email"]


@pytest.mark.asyncio
async def test_incremental_sync_and_deduplication():
    # Setup mock Gmail API service
    mock_service = MagicMock()

    # Initial profile historyId
    mock_service.users().getProfile().execute.return_value = {"historyId": "100500"}

    # Mock messages list
    mock_service.users().messages().list().execute.return_value = {
        "messages": [{"id": "msg-001"}, {"id": "msg-002"}]
    }

    # Mock raw message fetch
    encoded_raw = base64.urlsafe_b64encode(SAMPLE_RAW_RFC822).decode("utf-8")
    mock_service.users().messages().get().execute.return_value = {"raw": encoded_raw}

    # Reset deduplication cache
    PROCESSED_GMAIL_IDS.clear()
    gmail_oauth_manager.last_history_id = None

    with patch.object(gmail_oauth_manager, "get_gmail_service", return_value=mock_service):
        # 1. First sync - ingests both messages
        outcome1 = await gmail_oauth_manager.sync_inbox_incremental(limit=10)
        assert outcome1["status"] == "success"
        assert outcome1["new_messages_analyzed"] == 2
        assert outcome1["duplicates_skipped"] == 0
        assert "msg-001" in PROCESSED_GMAIL_IDS
        assert "msg-002" in PROCESSED_GMAIL_IDS

        # 2. Second sync - deduplication prevents re-scoring
        outcome2 = await gmail_oauth_manager.sync_inbox_incremental(limit=10)
        assert outcome2["status"] == "success"
        assert outcome2["new_messages_analyzed"] == 0
        assert outcome2["duplicates_skipped"] == 2


@pytest.mark.asyncio
async def test_history_api_stale_fallback():
    mock_service = MagicMock()

    # Simulate 404 HttpError on stale historyId
    resp_404 = MagicMock(status=404)
    http_err = HttpError(resp=resp_404, content=b"History ID expired")
    mock_service.users().history().list().execute.side_effect = http_err

    # Fallback to messages list succeeds
    mock_service.users().messages().list().execute.return_value = {"messages": []}
    mock_service.users().getProfile().execute.return_value = {"historyId": "200600"}

    gmail_oauth_manager.last_history_id = "old_expired_history_123"

    with patch.object(gmail_oauth_manager, "get_gmail_service", return_value=mock_service):
        outcome = await gmail_oauth_manager.sync_inbox_incremental(limit=10)
        assert outcome["status"] == "success"
        # History ID updated to new profile historyId
        assert gmail_oauth_manager.last_history_id == "200600"


def test_token_revocation_and_disconnect(client):
    # Set a test encrypted token
    gmail_oauth_manager.save_encrypted_token({
        "token": "ya29.mock_to_revoke",
        "refresh_token": "mock_refresh",
        "user_email": "revoked.user@gmail.com"
    })
    assert gmail_oauth_manager.token_enc_path.exists()

    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        res = client.post("/api/v1/oauth/gmail/disconnect")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "disconnected"

    # Token file removed
    assert not gmail_oauth_manager.token_enc_path.exists()
    assert gmail_oauth_manager.user_email is None

    # Status reflects disconnected
    status_res = client.get("/api/v1/oauth/gmail/status")
    assert status_res.json()["is_authorized"] is False
