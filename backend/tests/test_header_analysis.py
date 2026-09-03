from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SAMPLES = Path(__file__).parent / "sample_emails"


def upload(name: str):
    return client.post("/analyze", files={"file": (name, (SAMPLES / name).read_bytes(), "message/rfc822")})


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_legitimate_email_is_safe():
    result = upload("legit_email.eml")
    assert result.status_code == 200
    body = result.json()
    assert body["verdict"] == "safe"
    assert body["header_analysis"]["sender_ip"] == "8.8.8.8"


def test_typosquat_email_is_suspicious():
    body = upload("phishing_typosquat.eml").json()
    assert body["verdict"] == "suspicious"
    assert body["header_analysis"]["is_typosquat"] is True
    assert body["header_analysis"]["typosquat_target"] == "paypal.com"
    assert body["score"] >= 65


def test_authentication_failures_are_suspicious():
    body = upload("spf_dkim_fail.eml").json()
    assert body["verdict"] == "suspicious"
    assert body["score"] >= 65
    assert {item["rule"] for item in body["reasons"]} >= {"spf_fail", "dkim_fail", "dmarc_fail"}


def test_missing_auth_header_never_crashes():
    result = upload("missing_auth_header.eml")
    assert result.status_code == 200
    auth = result.json()["header_analysis"]["auth"]
    assert set(auth) == {"spf", "dkim", "dmarc", "source"}
    assert auth["source"] == "checkdmarc"


def test_json_body_without_file_is_accepted():
    raw_email = (SAMPLES / "legit_email.eml").read_text(encoding="utf-8")
    result = client.post("/analyze", json={"raw_email": raw_email})
    assert result.status_code == 200
    assert result.json()["header_analysis"]["from_domain"] == "example.org"


def test_softfail_is_preserved_and_scored():
    raw_email = """From: alerts@example.org\nAuthentication-Results: mx.example.net; spf=softfail; dkim=temperror; dmarc=permerror\n\nHello"""
    result = client.post("/analyze", json={"raw_email": raw_email})
    assert result.status_code == 200
    body = result.json()
    assert body["header_analysis"]["auth"] == {"spf": "softfail", "dkim": "temperror", "dmarc": "permerror", "source": "authentication-results-header"}
    assert any(reason["rule"] == "spf_softfail" and reason["points"] == 15 for reason in body["reasons"])


def test_garbage_is_a_clean_400():
    result = client.post("/analyze", json={"raw_email": "this is not an email"})
    assert result.status_code == 400
    assert "error" in result.json()


def test_empty_request_is_422():
    assert client.post("/analyze", json={}).status_code == 422
