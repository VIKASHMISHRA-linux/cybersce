"""
backend/websocket_server.py
High-performance WebSocket server with:
- Event-based pub/sub architecture
- Per-client subscriptions (logs, alerts)
- Heartbeat / ping-pong keep-alive
- Graceful shutdown
"""
import asyncio
import json
import logging
import time
from datetime import datetime

import websockets
from websockets.server import WebSocketServerProtocol

from backend.config import Config
from backend.core.log_processor import process_log
from backend.core.alert_manager import evaluate as evaluate_alert, register_callback
from backend.db import database as db

logger = logging.getLogger(__name__)

# ── Client registry ────────────────────────────────────────
_clients: set[WebSocketServerProtocol] = set()
_client_meta: dict[WebSocketServerProtocol, dict] = {}


def _broadcast_sync(event_type: str, payload: dict) -> None:
    """Schedule a broadcast from a sync context."""
    asyncio.create_task(_broadcast(event_type, payload))


async def _broadcast(event_type: str, payload: dict) -> None:
    """Send to all connected clients."""
    if not _clients:
        return
    msg = json.dumps({"type": event_type, "data": payload}, default=str)
    dead = set()
    for ws in _clients.copy():
        try:
            await ws.send(msg)
        except websockets.ConnectionClosed:
            dead.add(ws)
    for ws in dead:
        _remove_client(ws)


def _add_client(ws: WebSocketServerProtocol) -> None:
    _clients.add(ws)
    _client_meta[ws] = {"connected_at": time.time(), "messages": 0}
    logger.info("Client connected: %s (total=%d)", ws.remote_address, len(_clients))


def _remove_client(ws: WebSocketServerProtocol) -> None:
    _clients.discard(ws)
    _client_meta.pop(ws, None)
    logger.info("Client disconnected (total=%d)", len(_clients))


# ── Alert callback (registered with alert_manager) ─────────

async def _on_alert(alert: dict) -> None:
    await _broadcast("alert", alert)


register_callback(_on_alert)


# ── Message dispatcher ─────────────────────────────────────

async def _handle_message(ws: WebSocketServerProtocol, raw: str) -> None:
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        await ws.send(json.dumps({"type": "error", "data": "Invalid JSON"}))
        return

    msg_type = msg.get("type", "")
    data     = msg.get("data", {})

    if msg_type == "log":
        # Ingest a new log event
        event = await process_log(data)
        await _broadcast("log", event)
        alert = await evaluate_alert(event)
        if alert:
            await _broadcast("alert", alert)

    elif msg_type == "ping":
        await ws.send(json.dumps({"type": "pong", "ts": datetime.utcnow().isoformat()}))

    elif msg_type == "get_stats":
        stats = await _fetch_stats()
        await ws.send(json.dumps({"type": "stats", "data": stats}, default=str))

    elif msg_type == "subscribe":
        # Client can request initial data burst
        await _send_initial_data(ws)

    else:
        logger.debug("Unknown message type: %s", msg_type)


async def _fetch_stats() -> dict:
    try:
        row = await db.fetchone(
            """
            SELECT
              COUNT(*) AS total,
              SUM(risk_level IN ('high','critical')) AS high_risk,
              SUM(is_anomaly) AS anomalies
            FROM logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """
        )
        blocked = await db.fetchone("SELECT COUNT(*) AS c FROM blocked_ips")
        return {
            "total":      int(row["total"]     or 0),
            "high_risk":  int(row["high_risk"] or 0),
            "anomalies":  int(row["anomalies"] or 0),
            "blocked":    int(blocked["c"]     or 0),
            "clients":    len(_clients),
        }
    except Exception:
        return {}


async def _send_initial_data(ws: WebSocketServerProtocol) -> None:
    """Send last 20 logs + unread alerts on connect."""
    try:
        logs = await db.fetchall(
            """
            SELECT ip_address AS ip, message, risk_level AS risk, risk_score,
                   attack_type, country, city, isp, is_anomaly, created_at AS timestamp
            FROM logs ORDER BY created_at DESC LIMIT 20
            """
        )
        alerts = await db.fetchall(
            "SELECT * FROM alerts WHERE is_read=0 ORDER BY created_at DESC LIMIT 10"
        )
        await ws.send(json.dumps({
            "type": "init",
            "data": {"logs": logs, "alerts": alerts}
        }, default=str))
    except Exception as exc:
        logger.debug("Initial data send failed: %s", exc)


# ── Connection handler ─────────────────────────────────────

async def handler(ws: WebSocketServerProtocol) -> None:
    _add_client(ws)
    await _send_initial_data(ws)
    try:
        async for raw in ws:
            _client_meta[ws]["messages"] = _client_meta[ws].get("messages", 0) + 1
            await _handle_message(ws, raw)
    except websockets.ConnectionClosedOK:
        pass
    except websockets.ConnectionClosedError as exc:
        logger.debug("Connection closed with error: %s", exc)
    finally:
        _remove_client(ws)


# ── Heartbeat task ─────────────────────────────────────────

async def _heartbeat() -> None:
    while True:
        await asyncio.sleep(30)
        if _clients:
            msg = json.dumps({"type": "heartbeat", "ts": datetime.utcnow().isoformat()})
            dead = set()
            for ws in _clients.copy():
                try:
                    await ws.send(msg)
                except websockets.ConnectionClosed:
                    dead.add(ws)
            for ws in dead:
                _remove_client(ws)


# ── Entry point ────────────────────────────────────────────

async def start_server() -> None:
    await db.init_pool()
    asyncio.create_task(_heartbeat())

    async with websockets.serve(
        handler,
        Config.WS_HOST,
        Config.WS_PORT,
        ping_interval=20,
        ping_timeout=10,
        max_size=1_048_576,   # 1 MB
        compression=None,     # disable per-message deflate for lower latency
    ):
        logger.info("WebSocket server running on ws://%s:%d", Config.WS_HOST, Config.WS_PORT)
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    import backend.logger_setup  # noqa: F401
    asyncio.run(start_server())
