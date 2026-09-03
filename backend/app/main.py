from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from app.routes.analyze import router
from app.routes.auth import router as auth_router
from app.routes.frontend import router as frontend_router
from app.routes.gmail import router as gmail_router

app = FastAPI(title="Guardian Email Intel P1")
# Development-only permissive CORS; tighten this before public deployment.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
app.include_router(auth_router)
app.include_router(gmail_router)
app.include_router(frontend_router)


@app.websocket("/ws/live-feed")
async def live_feed(websocket: WebSocket) -> None:
    """Keep the UI socket connected in analyzer-only mode."""
    await websocket.accept()
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        await websocket.close()
