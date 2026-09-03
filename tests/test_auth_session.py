import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.app.api.v1.auth import CONNECTED_MAILBOXES, CURRENT_USER_SESSION


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_auth_session_initial(client):
    res = client.get("/api/v1/auth/session")
    assert res.status_code == 200
    data = res.json()
    assert "authenticated" in data
    assert "connected_mailboxes" in data
    assert isinstance(data["connected_mailboxes"], list)


def test_launch_demo_session(client):
    res = client.post("/api/v1/auth/demo", json={"scenario": "bec_wire_transfer"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "mailbox_id" in data
    assert data["scenario"] == "bec_wire_transfer"

    # Verify session now reports authenticated
    sess_res = client.get("/api/v1/auth/session")
    sess_data = sess_res.json()
    assert sess_data["authenticated"] is True
    assert sess_data["user"]["provider"] == "demo"
    assert sess_data["active_mailbox"] is not None


def test_logout_session(client):
    # Log out
    res = client.post("/api/v1/auth/logout")
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Check session
    sess_res = client.get("/api/v1/auth/session")
    assert sess_res.json()["authenticated"] is False
