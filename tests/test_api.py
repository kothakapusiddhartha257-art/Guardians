import base64
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.app.seeds.demo_emails import DEMO_BEC_EMAIL


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_root_endpoint(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "OPERATIONAL"


def test_upload_and_investigate_api(client):
    # 1. Upload email
    res = client.post(
        "/api/v1/emails",
        data={"raw_content": DEMO_BEC_EMAIL, "case_id": "CASE-API-TEST-01"}
    )
    assert res.status_code == 202
    data = res.json()
    email_id = data["email_id"]
    assert data["threat_score"] > 0.70

    # 2. Get full investigation
    inv_res = client.get(f"/api/v1/emails/{email_id}")
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    assert inv_data["risk_score"]["classification"] == "BEC"

    # 3. Get PDF report
    pdf_res = client.get(f"/api/v1/emails/{email_id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

    # 4. Get STIX report
    stix_res = client.get(f"/api/v1/emails/{email_id}/stix.json")
    assert stix_res.status_code == 200
    assert stix_res.json()["type"] == "bundle"

    # 5. Dashboard summary
    dash_res = client.get("/api/v1/dashboard/summary")
    assert dash_res.status_code == 200
    assert dash_res.json()["emails_analyzed"] >= 1


def test_ingest_raw_email_endpoint(client):
    # Test base64 ingestion from extension
    b64_eml = base64.b64encode(DEMO_BEC_EMAIL.encode("utf-8")).decode("utf-8")
    res = client.post("/api/v1/emails/ingest", json={
        "raw_eml_base64": b64_eml,
        "gmail_message_id": "18f0a3e8b4c2d1e0",
        "case_id": "CASE-EXT-TEST-01"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETE"
    assert data["threat_score"] > 0.70
    assert data["classification"] == "BEC"
    assert "key_signals" in data
    assert "auth" in data
    assert data["auth"]["spf"] in ["FAIL", "NONE", "PASS"]
    assert data["gmail_message_id"] == "18f0a3e8b4c2d1e0"
