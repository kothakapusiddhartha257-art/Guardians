import pytest
from fastapi.testclient import TestClient
from backend.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_live_gateway_api_flow(client):
    # 1. Check mailbox connections
    m_res = client.get("/api/v1/mailboxes")
    assert m_res.status_code == 200
    mailboxes = m_res.json()
    assert len(mailboxes) >= 1

    # 2. Trigger live inbound threat simulation
    sim_res = client.post("/api/v1/mailboxes/simulate-incoming", json={"scenario": "bec"})
    assert sim_res.status_code == 200
    record = sim_res.json()
    assert record["action_taken"] == "QUARANTINE"
    assert record["threat_score"] >= 0.75
    assert record["email_id"] is not None

    # 3. Check live feed endpoint
    feed_res = client.get("/api/v1/emails/live")
    assert feed_res.status_code == 200
    feed_items = feed_res.json()
    assert len(feed_items) >= 1
    assert feed_items[0]["action_taken"] == "QUARANTINE"

    # 4. Analyst manual action override
    rec_id = feed_items[0]["id"]
    override_res = client.post(
        f"/api/v1/emails/live/{rec_id}/override-action",
        json={"action": "FLAG", "reason": "Analyst verified benign testing context", "analyst": "analyst_01"}
    )
    assert override_res.status_code == 200
    updated_rec = override_res.json()
    assert updated_rec["action_taken"] == "FLAG"
