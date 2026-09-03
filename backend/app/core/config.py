import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "data" / "evidence"
GEOIP_DIR = BASE_DIR / "data" / "geoip"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
GEOIP_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    PROJECT_NAME: str = "TRACEGUARD AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "traceguard-insecure-supersecret-jwt-key-2026-sih")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database URL: sqlite+aiosqlite for standalone portability, or postgresql+asyncpg
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'traceguard.db'}"
    )
    
    # Neo4j Settings (Optional / fallback to embedded NetworkX)
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "traceguard2026")
    USE_NEO4J: bool = os.getenv("USE_NEO4J", "False").lower() in ("true", "1", "yes")

    # Risk Fusion Starting Weights
    FUSION_WEIGHTS: dict = {
        "nlp": 0.20,
        "structural": 0.15,
        "header": 0.15,
        "url": 0.10,
        "domain": 0.10,
        "ip": 0.10,
        "relay": 0.08,
        "attachment": 0.07,
        "behavior": 0.05
    }

    # Protected VIP Brands for Lookalike / Homoglyph Detection
    PROTECTED_BRANDS: list = [
        "microsoft", "office365", "google", "gmail", "apple", "amazon",
        "paypal", "chase", "bankofamerica", "wellsfargo", "dhl", "fedex",
        "docu-sign", "docusign", "dropbox", "irs", "incometax", "gov", "sbi", "hdfc", "icici"
    ]

    # Gmail IMAP Ingestion Settings (Backend-only, never exposed to clients)
    GMAIL_EMAIL: str = os.getenv("GMAIL_EMAIL", "kingkmn786@gmail.com")
    GMAIL_APP_PASSWORD: str = os.getenv("GMAIL_APP_PASSWORD", "")
    IMAP_HOST: str = os.getenv("IMAP_HOST", "imap.gmail.com")
    IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
    IMAP_FOLDER: str = os.getenv("IMAP_FOLDER", "INBOX")
    GMAIL_AUTO_SCAN: bool = os.getenv("GMAIL_AUTO_SCAN", "False").lower() in ("true", "1", "yes")
    GMAIL_AUTO_SCAN_INTERVAL_MINUTES: int = int(os.getenv("GMAIL_AUTO_SCAN_INTERVAL_MINUTES", "5"))

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "case_sensitive": False
    }

settings = Settings()
