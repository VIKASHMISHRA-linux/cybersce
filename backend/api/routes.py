"""
backend/api/routes.py
All REST endpoints for the CyberSec Dashboard.
"""
import json
import logging
from datetime import datetime, timedelta

from aiohttp import web

from backend.api.auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    save_refresh_token, revoke_refresh_token, validate_refresh_token,
    decode_token, require_auth, require_admin, rate_limit,
)
from backend.db import database as db

logger = logging.getLogger(__name__)
routes = web.RouteTableDef()


# ── Helpers ────────────────────────────────────────────────

def _json(data, status=200):
    return web.Response(
        text=json.dumps(data, default=str),
        content_type="application/json",
        status=status,
    )


def _validate(data: dict, required: list[str]) -> str | None:
    for field in required:
        if not data.get(field):
            return f"Missing field: {field}"
    return None


# ══════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════

@routes.post("/api/auth/login")
@rate_limit
async def login(request: web.Request):
    body = await request.json()
    err  = _validate(body, ["username", "password"])
    if err:
        return _json({"error": err}, 400)

    user = await db.fetchone(
        "SELECT * FROM users WHERE username=%s AND is_active=1", (body["username"],)
    )
    if not user or not verify_password(body["password"], user["password_hash"]):
        return _json({"error": "Invalid credentials"}, 401)

    access  = create_access_token(user["id"], user["role"])
    refresh = create_refresh_token(user["id"])
    await save_refresh_token(user["id"], refresh)
    await db.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))

    return _json({
        "access_token":  access,
        "refresh_token": refresh,
        "role":          user["role"],
        "username":      user["username"],
    })


@routes.post("/api/auth/refresh")
async def refresh_token(request: web.Request):
    body = await request.json()
    token = body.get("refresh_token")
    if not token:
        return _json({"error": "Missing refresh_token"}, 400)

    row = await validate_refresh_token(token)
    if not row:
        return _json({"error": "Invalid or expired refresh token"}, 401)

    try:
        payload = decode_token(token)
    except Exception:
        return _json({"error": "Invalid token"}, 401)

    user = await db.fetchone("SELECT * FROM users WHERE id=%s", (payload["sub"],))
    if not user:
        return _json({"error": "User not found"}, 404)

    await revoke_refresh_token(token)
    new_access  = create_access_token(user["id"], user["role"])
    new_refresh = create_refresh_token(user["id"])
    await save_refresh_token(user["id"], new_refresh)

    return _json({"access_token": new_access, "refresh_token": new_refresh})


@routes.post("/api/auth/logout")
@require_auth
async def logout(request: web.Request):
    body = await request.json()
    token = body.get("refresh_token")
    if token:
        await revoke_refresh_token(token)
    return _json({"message": "Logged out"})


@routes.post("/api/auth/register")
@require_admin
async def register(request: web.Request):
    body = await request.json()
    err  = _validate(body, ["username", "email", "password"])
    if err:
        return _json({"error": err}, 400)

    if len(body["password"]) < 8:
        return _json({"error": "Password must be at least 8 characters"}, 400)

    try:
        uid = await db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)",
            (body["username"], body["email"],
             hash_password(body["password"]), body.get("role", "user")),
        )
        return _json({"id": uid, "message": "User created"}, 201)
    except Exception as exc:
        if "Duplicate" in str(exc):
            return _json({"error": "Username or email already exists"}, 409)
        raise


# ══════════════════════════════════════════════════════════
# LOGS ENDPOINTS
# ══════════════════════════════════════════════════════════

@routes.get("/api/logs")
@require_auth
async def get_logs(request: web.Request):
    limit  = min(int(request.rel_url.query.get("limit",  "100")), 500)
    offset = int(request.rel_url.query.get("offset", "0"))
    risk   = request.rel_url.query.get("risk")
    ip     = request.rel_url.query.get("ip")

    where, args = ["1=1"], []
    if risk:
        where.append("risk_level=%s"); args.append(risk)
    if ip:
        where.append("ip_address=%s"); args.append(ip)

    sql = f"""
        SELECT id, ip_address, message, risk_level, risk_score,
               attack_type, country, city, isp, is_anomaly, created_at
        FROM logs WHERE {' AND '.join(where)}
        ORDER BY created_at DESC LIMIT %s OFFSET %s
    """
    rows = await db.fetchall(sql, (*args, limit, offset))
    total = await db.fetchone(
        f"SELECT COUNT(*) AS c FROM logs WHERE {' AND '.join(where)}", tuple(args)
    )
    return _json({"logs": rows, "total": total["c"], "limit": limit, "offset": offset})


@routes.get("/api/logs/{log_id}")
@require_auth
async def get_log(request: web.Request):
    row = await db.fetchone(
        "SELECT * FROM logs WHERE id=%s", (request.match_info["log_id"],)
    )
    if not row:
        return _json({"error": "Not found"}, 404)
    return _json(row)


# ══════════════════════════════════════════════════════════
# ALERTS ENDPOINTS
# ══════════════════════════════════════════════════════════

@routes.get("/api/alerts")
@require_auth
async def get_alerts(request: web.Request):
    limit    = min(int(request.rel_url.query.get("limit", "50")), 200)
    unread   = request.rel_url.query.get("unread") == "1"
    where    = "is_read=0" if unread else "1=1"
    rows     = await db.fetchall(
        f"SELECT * FROM alerts WHERE {where} ORDER BY created_at DESC LIMIT %s", (limit,)
    )
    return _json({"alerts": rows})


@routes.patch("/api/alerts/{alert_id}/read")
@require_auth
async def mark_read(request: web.Request):
    await db.execute(
        "UPDATE alerts SET is_read=1 WHERE id=%s", (request.match_info["alert_id"],)
    )
    return _json({"message": "Marked as read"})


@routes.patch("/api/alerts/read-all")
@require_auth
async def mark_all_read(request: web.Request):
    await db.execute("UPDATE alerts SET is_read=1 WHERE is_read=0")
    return _json({"message": "All alerts marked as read"})


# ══════════════════════════════════════════════════════════
# ANALYTICS ENDPOINTS
# ══════════════════════════════════════════════════════════

@routes.get("/api/analytics/daily-trend")
@require_auth
async def daily_trend(request: web.Request):
    days = int(request.rel_url.query.get("days", "7"))
    rows = await db.fetchall(
        """
        SELECT DATE(created_at) AS day,
               COUNT(*) AS total,
               SUM(risk_level IN ('high','critical')) AS high_risk
        FROM logs
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
        GROUP BY DATE(created_at)
        ORDER BY day ASC
        """,
        (days,),
    )
    return _json({"trend": rows})


@routes.get("/api/analytics/top-ips")
@require_auth
async def top_ips(request: web.Request):
    limit = min(int(request.rel_url.query.get("limit", "10")), 50)
    rows  = await db.fetchall(
        """
        SELECT ip_address, COUNT(*) AS hits,
               MAX(risk_score) AS max_score,
               MAX(country) AS country
        FROM logs
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY ip_address
        ORDER BY hits DESC LIMIT %s
        """,
        (limit,),
    )
    return _json({"top_ips": rows})


@routes.get("/api/analytics/attack-types")
@require_auth
async def attack_types(request: web.Request):
    rows = await db.fetchall(
        """
        SELECT attack_type, COUNT(*) AS count
        FROM logs
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
          AND attack_type IS NOT NULL
        GROUP BY attack_type
        ORDER BY count DESC
        """,
    )
    return _json({"attack_types": rows})


@routes.get("/api/analytics/country-stats")
@require_auth
async def country_stats(request: web.Request):
    rows = await db.fetchall(
        """
        SELECT country, COUNT(*) AS total,
               SUM(risk_level IN ('high','critical')) AS high_risk
        FROM logs
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
          AND country IS NOT NULL
        GROUP BY country
        ORDER BY total DESC LIMIT 15
        """,
    )
    return _json({"countries": rows})


@routes.get("/api/analytics/summary")
@require_auth
async def summary(request: web.Request):
    stats = await db.fetchone(
        """
        SELECT
          COUNT(*) AS total_logs,
          SUM(risk_level IN ('high','critical')) AS high_risk,
          SUM(is_anomaly) AS anomalies,
          AVG(risk_score) AS avg_score
        FROM logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """
    )
    blocked = await db.fetchone("SELECT COUNT(*) AS c FROM blocked_ips")
    unread  = await db.fetchone("SELECT COUNT(*) AS c FROM alerts WHERE is_read=0")
    return _json({
        **stats,
        "blocked_ips":    blocked["c"],
        "unread_alerts":  unread["c"],
    })


# ══════════════════════════════════════════════════════════
# ADMIN ENDPOINTS
# ══════════════════════════════════════════════════════════

@routes.get("/api/admin/users")
@require_admin
async def list_users(request: web.Request):
    rows = await db.fetchall(
        "SELECT id, username, email, role, is_active, last_login, created_at FROM users"
    )
    return _json({"users": rows})


@routes.patch("/api/admin/users/{user_id}/toggle")
@require_admin
async def toggle_user(request: web.Request):
    uid = request.match_info["user_id"]
    await db.execute(
        "UPDATE users SET is_active = NOT is_active WHERE id=%s", (uid,)
    )
    return _json({"message": "User status toggled"})


@routes.post("/api/admin/block-ip")
@require_admin
async def block_ip(request: web.Request):
    body = await request.json()
    ip   = body.get("ip")
    if not ip:
        return _json({"error": "IP required"}, 400)

    admin_id = int(request["user"]["sub"])
    try:
        await db.execute(
            "INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (%s,%s,%s)",
            (ip, body.get("reason", "Manual block"), admin_id),
        )
        await db.execute(
            "UPDATE ip_reputation SET is_blocked=1 WHERE ip_address=%s", (ip,)
        )
        return _json({"message": f"{ip} blocked"}, 201)
    except Exception as exc:
        if "Duplicate" in str(exc):
            return _json({"error": "IP already blocked"}, 409)
        raise


@routes.delete("/api/admin/block-ip/{ip}")
@require_admin
async def unblock_ip(request: web.Request):
    ip = request.match_info["ip"]
    await db.execute("DELETE FROM blocked_ips WHERE ip_address=%s", (ip,))
    await db.execute("UPDATE ip_reputation SET is_blocked=0 WHERE ip_address=%s", (ip,))
    return _json({"message": f"{ip} unblocked"})


@routes.get("/api/admin/blocked-ips")
@require_admin
async def list_blocked(request: web.Request):
    rows = await db.fetchall(
        """
        SELECT b.*, u.username AS blocked_by_name
        FROM blocked_ips b
        LEFT JOIN users u ON b.blocked_by = u.id
        ORDER BY b.blocked_at DESC
        """
    )
    return _json({"blocked_ips": rows})


@routes.get("/api/admin/system-logs")
@require_admin
async def system_logs(request: web.Request):
    try:
        from backend.config import Config as C
        with open(C.LOG_FILE, "r") as f:
            lines = f.readlines()[-200:]
        return _json({"lines": [l.rstrip() for l in lines]})
    except FileNotFoundError:
        return _json({"lines": []})


# ── CORS middleware ────────────────────────────────────────

@web.middleware
async def cors_middleware(request: web.Request, handler):
    if request.method == "OPTIONS":
        return web.Response(headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
        })
    response = await handler(request)
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app.add_routes(routes)
    return app
