import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.app.services.email_ingestion.gmail_oauth import gmail_oauth_manager


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
    assert any("mail.google.com" in s for s in data["scopes"])


def test_gmail_oauth_credentials_save(client):
    res = client.post("/api/v1/oauth/gmail/credentials", json={
        "client_id": "test-client-12345.apps.googleusercontent.com",
        "client_secret": "test_mock_secret_key_12345",
        "redirect_uri": "http://127.0.0.1:8000/api/v1/oauth/gmail/callback"
    })
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Verify status reflects updated credentials
    status_res = client.get("/api/v1/oauth/gmail/status")
    assert status_res.status_code == 200
    assert status_res.json()["is_configured"] is True


def test_gmail_oauth_auth_url_generation(client):
    res = client.get("/api/v1/oauth/gmail/auth-url")
    assert res.status_code == 200
    data = res.json()
    assert "auth_url" in data
    assert "accounts.google.com" in data["auth_url"]
    assert "client_id=" in data["auth_url"]


def test_xoauth2_string_generation():
    xoauth_str = gmail_oauth_manager.generate_xoauth2_string(
        username="admin@domain.com",
        access_token="ya29.sample_token_value"
    )
    assert len(xoauth_str) > 20
    import base64
    decoded = base64.b64decode(xoauth_str).decode("utf-8")
    assert "user=admin@domain.com" in decoded
    assert "auth=Bearer ya29.sample_token_value" in decoded
