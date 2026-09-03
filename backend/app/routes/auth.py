"""Local analyst login for the standalone development deployment.

Credentials come from .env; no credentials are hard-coded in source. Replace
them before exposing this app beyond your own machine.
"""
from __future__ import annotations

import os
import secrets

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/auth", tags=["local analyst auth"])
_sessions: dict[str, str] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


def _subject(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return _sessions.get(authorization.removeprefix("Bearer "))


def _configured_users() -> dict[str, str]:
    """Read comma-separated username:password pairs from local .env."""
    users: dict[str, str] = {}
    for entry in os.getenv("LOCAL_ANALYST_USERS", "").split(","):
        username, separator, password = entry.strip().partition(":")
        if separator and username and password:
            users[username] = password
    # Backward compatibility for the original single-account configuration.
    if not users:
        username = os.getenv("LOCAL_ANALYST_USERNAME", "")
        password = os.getenv("LOCAL_ANALYST_PASSWORD", "")
        if username and password:
            users[username] = password
    return users


@router.post("/login")
def login(request: LoginRequest) -> dict:
    users = _configured_users()
    if not users:
        raise HTTPException(503, "Local analyst login is not configured. Set LOCAL_ANALYST_USERS in .env.")
    expected_password = users.get(request.username)
    if expected_password is None or not secrets.compare_digest(request.password, expected_password):
        raise HTTPException(401, "Invalid analyst ID or password.")
    token = secrets.token_urlsafe(32)
    _sessions[token] = request.username
    return {"access_token": token, "token_type": "bearer", "username": request.username, "role": "ANALYST"}


@router.get("/session")
def session(authorization: str | None = Header(None)) -> dict:
    username = _subject(authorization)
    return {"authenticated": bool(username), "user": {"email": username, "provider": "local", "role": "ANALYST"} if username else None,
            "active_mailbox": None, "connected_mailboxes": []}


@router.post("/logout")
def logout(authorization: str | None = Header(None)) -> dict:
    if authorization and authorization.startswith("Bearer "):
        _sessions.pop(authorization.removeprefix("Bearer "), None)
    return {"status": "logged_out"}
