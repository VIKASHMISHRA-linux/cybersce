"""
backend/config.py
Central configuration — reads from environment / .env file.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Database ──────────────────────────────────────────
    DB_HOST     = os.getenv("DB_HOST",     "localhost")
    DB_PORT     = int(os.getenv("DB_PORT", "3306"))
    DB_USER     = os.getenv("DB_USER",     "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME     = os.getenv("DB_NAME",     "cybersec_db")

    # ── JWT ───────────────────────────────────────────────
    JWT_SECRET          = os.getenv("JWT_SECRET",  "change-me-in-production-32chars!")
    JWT_ALGORITHM       = "HS256"
    JWT_ACCESS_EXPIRE   = int(os.getenv("JWT_ACCESS_EXPIRE",  "900"))    # 15 min
    JWT_REFRESH_EXPIRE  = int(os.getenv("JWT_REFRESH_EXPIRE", "604800")) # 7 days

    # ── WebSocket ─────────────────────────────────────────
    WS_HOST = os.getenv("WS_HOST", "0.0.0.0")
    WS_PORT = int(os.getenv("WS_PORT", "8765"))

    # ── API Server ────────────────────────────────────────
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "8000"))

    # ── Email Alerts ──────────────────────────────────────
    SMTP_HOST     = os.getenv("SMTP_HOST",     "smtp.gmail.com")
    SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER     = os.getenv("SMTP_USER",     "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL   = os.getenv("ALERT_EMAIL",   "")

    # ── AI / Risk ─────────────────────────────────────────
    RISK_THRESHOLD_HIGH     = int(os.getenv("RISK_THRESHOLD_HIGH",     "60"))
    RISK_THRESHOLD_CRITICAL = int(os.getenv("RISK_THRESHOLD_CRITICAL", "80"))
    ANOMALY_CONTAMINATION   = float(os.getenv("ANOMALY_CONTAMINATION", "0.1"))

    # ── Rate Limiting ─────────────────────────────────────
    RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW",   "60"))   # seconds

    # ── Logging ───────────────────────────────────────────
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE  = os.getenv("LOG_FILE",  "backend/logs/app.log")
