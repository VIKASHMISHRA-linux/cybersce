"""
backend/core/alert_manager.py
Threshold-based alert creation, DB persistence, and email dispatch.
"""
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

from backend.config import Config
from backend.db import database as db

logger = logging.getLogger(__name__)

# Callbacks registered by WebSocket server to push alerts live
_alert_callbacks: list = []


def register_callback(fn) -> None:
    _alert_callbacks.append(fn)


async def evaluate(event: dict) -> dict | None:
    """
    Check if event crosses alert threshold.
    Returns alert dict if triggered, else None.
    """
    score = event.get("risk_score", 0)
    risk  = event.get("risk", "low")

    if score < Config.RISK_THRESHOLD_HIGH and risk not in ("high", "critical"):
        return None

    severity   = "critical" if score >= Config.RISK_THRESHOLD_CRITICAL else "high"
    alert_type = _determine_type(event)

    alert = {
        "ip_address":  event["ip"],
        "alert_type":  alert_type,
        "severity":    severity,
        "message":     _build_message(event, alert_type),
        "risk_score":  score,
        "log_id":      event.get("id"),
        "country":     event.get("country", "Unknown"),
        "city":        event.get("city",    "Unknown"),
        "timestamp":   datetime.utcnow().isoformat() + "Z",
    }

    # Persist
    alert_id = await _save_alert(alert)
    alert["id"] = alert_id

    # Broadcast live
    for cb in _alert_callbacks:
        try:
            await cb(alert)
        except Exception as exc:
            logger.debug("Alert callback error: %s", exc)

    # Email (fire-and-forget)
    if Config.SMTP_USER and Config.ALERT_EMAIL:
        asyncio.create_task(_send_email(alert))

    logger.warning("ALERT [%s] ip=%s score=%d", severity.upper(), event["ip"], score)
    return alert


def _determine_type(event: dict) -> str:
    attack = event.get("attack_type", "normal")
    if attack != "normal":
        return attack
    if event.get("is_anomaly"):
        return "anomaly"
    return "threshold_breach"


def _build_message(event: dict, alert_type: str) -> str:
    return (
        f"{alert_type.replace('_',' ').title()} detected from "
        f"{event['ip']} ({event.get('city','?')}, {event.get('country','?')}) "
        f"— Risk Score: {event['risk_score']}/100"
    )


async def _save_alert(alert: dict) -> int | None:
    try:
        return await db.execute(
            """
            INSERT INTO alerts
              (log_id, ip_address, alert_type, severity, message, risk_score)
            VALUES (%s,%s,%s,%s,%s,%s)
            """,
            (
                alert.get("log_id"), alert["ip_address"],
                alert["alert_type"], alert["severity"],
                alert["message"],   alert["risk_score"],
            ),
        )
    except Exception as exc:
        logger.error("Failed to save alert: %s", exc)
        return None


async def _send_email(alert: dict) -> None:
    subject = f"[CyberSec] {alert['severity'].upper()} Alert — {alert['ip_address']}"
    body = (
        f"Severity  : {alert['severity'].upper()}\n"
        f"Type      : {alert['alert_type']}\n"
        f"IP        : {alert['ip_address']}\n"
        f"Location  : {alert['city']}, {alert['country']}\n"
        f"Risk Score: {alert['risk_score']}/100\n"
        f"Message   : {alert['message']}\n"
        f"Time      : {alert['timestamp']}\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = Config.SMTP_USER
    msg["To"]      = Config.ALERT_EMAIL

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _smtp_send, msg)
        await db.execute(
            "UPDATE alerts SET email_sent=1 WHERE id=%s", (alert.get("id"),)
        )
    except Exception as exc:
        logger.error("Email send failed: %s", exc)


def _smtp_send(msg: MIMEText) -> None:
    with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as s:
        s.starttls()
        s.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        s.send_message(msg)
