import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.models.entities import init_db
from backend.app.seeds.demo_emails import seed_demo_database
from backend.app.api.v1.emails import router as emails_router
from backend.app.api.v1.cases import router as cases_router
from backend.app.api.v1.dashboard import router as dashboard_router
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.mailboxes import router as mailboxes_router
from backend.app.api.v1.live_feed import router as live_feed_router
from backend.app.api.v1.oauth import router as oauth_router
from backend.app.services.email_monitor import email_monitor


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables & pre-seed historical demo intelligence
    await init_db()
    await seed_demo_database()
    yield
    # Shutdown logic if needed


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    lifespan=lifespan
)

# Enable CORS for Frontend Analyst Console
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api/v1 (live_feed mounted before emails to take precedence over /{email_id})
app.include_router(live_feed_router, prefix=settings.API_V1_STR)
app.include_router(mailboxes_router, prefix=settings.API_V1_STR)
app.include_router(oauth_router, prefix=settings.API_V1_STR)
app.include_router(emails_router, prefix=settings.API_V1_STR)
app.include_router(cases_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "gateway_active": True,
        "docs_url": "/docs",
        "api_v1": settings.API_V1_STR
    }


@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    email_monitor.websocket_subscribers.add(websocket)
    try:
        # Keep connection open and send initial state
        await websocket.send_json({
            "type": "INITIAL_STATE",
            "active_mailboxes": len(email_monitor.active_connections),
            "recent_count": len(email_monitor.live_email_records)
        })
        while True:
            # Keep-alive heartbeat ping
            await asyncio.sleep(15)
            await websocket.send_json({"type": "HEARTBEAT"})
    except WebSocketDisconnect:
        email_monitor.websocket_subscribers.discard(websocket)
    except Exception:
        email_monitor.websocket_subscribers.discard(websocket)


@app.websocket("/ws/emails/{email_id}")
async def websocket_email_status(websocket: WebSocket, email_id: str):
    await websocket.accept()
    try:
        stages = [
            ("evidence_preservation", 15),
            ("mime_header_parsing", 30),
            ("auth_forensics_spf_dkim_dmarc", 45),
            ("relay_trust_frontier", 60),
            ("domain_and_url_intelligence", 75),
            ("nlp_and_structural_ml", 90),
            ("risk_fusion_and_correlation", 100)
        ]
        for stage_name, progress in stages:
            await websocket.send_json({
                "email_id": email_id,
                "stage": stage_name,
                "progress": progress,
                "status": "PROCESSING" if progress < 100 else "COMPLETE"
            })
            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass
