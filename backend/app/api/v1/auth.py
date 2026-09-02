from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from backend.app.core.security import create_access_token, verify_password, get_password_hash

router = APIRouter(prefix="/auth", tags=["Auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(req: LoginRequest):
    # Built-in demo analysts for quick login without friction
    if req.username in ("analyst_01", "admin", "investigator") and req.password in ("traceguard2026", "admin", "password"):
        token = create_access_token(subject=req.username)
        return {
            "access_token": token,
            "token_type": "bearer",
            "username": req.username,
            "role": "ADMIN" if req.username == "admin" else "ANALYST"
        }
    
    # Allow any demo analyst login
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
