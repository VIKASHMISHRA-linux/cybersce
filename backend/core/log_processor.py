"""
backend/core/log_processor.py
Central pipeline: raw log → AI enrichment → DB persist → broadcast payload.
"""
import json
import logging
from datetime import datetime

from backend.ai.threat_engine import ip_tracker, anomaly_det, risk_scorer, classifier
from backend.ai.geoip import lookup as geo_lookup, country_flag
from backend.db import database as db

logger = logging.getLogger(__name__)


async def process_log(raw: dict) -> dict:
    """
    Accepts a raw log dict with at minimum: {ip, message}.
    Returns enriched event dict ready for WebSocket broadcast + DB storage.
    """
    ip      = raw.get("ip", "0.0.0.0")
    message = raw.get("message", "")
    failed  = raw.get("failed", False)
    port    = raw.get("port")

    # ── 1. Behaviour tracking ──────────────────────────────
    behaviour = ip_tracker.record(ip, failed=failed, port=port)

    # ── 2. GeoIP ──────────────────────────────────────────
    geo = await geo_lookup(ip)

    # ── 3. Abuse score from DB reputation ─────────────────
    rep = await db.fetchone(
        "SELECT abuse_score, is_blocked FROM ip_reputation WHERE ip_address = %s", (ip,)
    )
    abuse_score = int(rep["abuse_score"]) if rep else 0
    is_blocked  = bool(rep["is_blocked"]) if rep else False

    # ── 4. Attack classification ───────────────────────────
    attack_type = classifier.classify(message)

    # ── 5. Anomaly detection ───────────────────────────────
    is_anomaly, anomaly_score = anomaly_det.predict(behaviour, abuse_score)

    # ── 6. Risk scoring ────────────────────────────────────
    risk_score, risk_level = risk_scorer.compute(
        behaviour     = behaviour,
        abuse_score   = abuse_score,
        anomaly_score = anomaly_score,
        attack_type   = attack_type,
        country_code  = geo.get("country_code", ""),
        is_blocked    = is_blocked,
    )

    # ── 7. Persist to DB ───────────────────────────────────
    log_id = await _save_log(
        ip, message, risk_level, risk_score, attack_type, geo, is_anomaly, raw
    )

    # ── 8. Update ip_reputation counters ──────────────────
    await _update_reputation(ip, failed, geo)

    # ── 9. Build broadcast payload ─────────────────────────
    event = {
        "id":           log_id,
        "ip":           ip,
        "message":      message,
        "risk":         risk_level,
        "risk_score":   risk_score,
        "attack_type":  attack_type,
        "is_anomaly":   is_anomaly,
        "country":      geo.get("country",  "Unknown"),
        "country_code": geo.get("country_code", "XX"),
        "city":         geo.get("city",     "Unknown"),
        "isp":          geo.get("isp",      "Unknown"),
        "latitude":     geo.get("latitude",  0.0),
        "longitude":    geo.get("longitude", 0.0),
        "flag":         country_flag(geo.get("country_code", "XX")),
        "location":     f"{geo.get('city','?')}, {geo.get('country','?')}",
        "behaviour":    behaviour,
        "timestamp":    datetime.utcnow().isoformat() + "Z",
    }

    logger.debug("Processed log ip=%s risk=%s score=%d", ip, risk_level, risk_score)
    return event


# ── DB helpers ─────────────────────────────────────────────

async def _save_log(ip, message, risk_level, risk_score, attack_type, geo, is_anomaly, raw):
    try:
        return await db.execute(
            """
            INSERT INTO logs
              (ip_address, message, risk_level, risk_score, attack_type,
               country, city, isp, latitude, longitude, is_anomaly, raw_data)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                ip, message, risk_level, risk_score, attack_type,
                geo.get("country"), geo.get("city"), geo.get("isp"),
                geo.get("latitude"), geo.get("longitude"),
                int(is_anomaly), json.dumps(raw),
            ),
        )
    except Exception as exc:
        logger.error("Failed to save log: %s", exc)
        return None


async def _update_reputation(ip: str, failed: bool, geo: dict) -> None:
    try:
        await db.execute(
            """
            INSERT INTO ip_reputation
              (ip_address, country, city, isp, latitude, longitude,
               request_count, fail_count, last_seen)
            VALUES (%s,%s,%s,%s,%s,%s,1,%s,NOW(3))
            ON DUPLICATE KEY UPDATE
              request_count = request_count + 1,
              fail_count    = fail_count + %s,
              last_seen     = NOW(3)
            """,
            (
                ip,
                geo.get("country"), geo.get("city"), geo.get("isp"),
                geo.get("latitude"), geo.get("longitude"),
                int(failed),
                int(failed),
            ),
        )
    except Exception as exc:
        logger.debug("Reputation update failed: %s", exc)
