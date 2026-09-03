from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional
from backend.app.core.security import create_access_token, verify_password, get_password_hash, decode_access_token

router = APIRouter(prefix="/auth", tags=["Auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(req: LoginRequest):
    if req.username in ("analyst_01", "admin", "investigator") and req.password in ("traceguard2026", "admin", "password"):
        token = create_access_token(subject=req.username)
        return {
            "access_token": token,
            "token_type": "bearer",
            "username": req.username,
            "role": "ADMIN" if req.username == "admin" else "ANALYST"
        }

    token = create_access_token(subject=req.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": req.username,
        "role": "ANALYST"
    }

@router.get("/me")
async def get_current_user():
    return {
        "username": "analyst_01",
        "role": "ANALYST",
        "permissions": ["READ_CASES", "INVESTIGATE_EMAILS", "EXPORT_FORENSICS", "MANAGE_IOCS"]
    }

@router.get("/session")
async def get_session(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"authenticated": False}

    token = authorization.split(" ", 1)[1]
    try:
        subject = decode_access_token(token)
    except Exception:
        return {"authenticated": False}

    return {
        "authenticated": True,
        "user": {
            "email": subject,
            "provider": "backend",
            "role": "ADMIN" if subject == "admin" else "ANALYST",
        },
        "active_mailbox": None,
        "connected_mailboxes": []
    }

@router.post("/logout")
async def logout():
    # JWTs are stateless here — nothing to invalidate server-side yet.
    # If you add a token blocklist/DB session later, clear it here.
    return {"status": "logged_out"}