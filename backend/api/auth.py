"""
backend/api/auth.py
JWT access + refresh tokens, bcrypt password hashing, RBAC decorators.
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from aiohttp import web

from backend.config import Config
from backend.db import database as db

logger = logging.getLogger(__name__)


# ── Password helpers ───────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── Token helpers ──────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(user_id: int, role: str) -> str:
    payload = {
        "sub":  str(user_id),
        "role": role,
        "exp":  _now() + timedelta(seconds=Config.JWT_ACCESS_EXPIRE),
        "iat":  _now(),
        "type": "access",
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    payload = {
        "sub":  str(user_id),
        "exp":  _now() + timedelta(seconds=Config.JWT_REFRESH_EXPIRE),
        "iat":  _now(),
        "type": "refresh",
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def save_refresh_token(user_id: int, token: str) -> None:
    expires = _now() + timedelta(seconds=Config.JWT_REFRESH_EXPIRE)
    await db.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (%s,%s,%s)",
        (user_id, _token_hash(token), expires),
    )


async def revoke_refresh_token(token: str) -> None:
    await db.execute(
        "DELETE FROM refresh_tokens WHERE token_hash=%s", (_token_hash(token),)
    )


async def validate_refresh_token(token: str) -> dict | None:
    row = await db.fetchone(
        "SELECT * FROM refresh_tokens WHERE token_hash=%s AND expires_at > NOW()",
        (_token_hash(token),),
    )
    return row


# ── Request helpers ────────────────────────────────────────

def _extract_token(request: web.Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("access_token")


# ── RBAC decorators ────────────────────────────────────────

def require_auth(handler):
    """Require valid JWT access token."""
    @wraps(handler)
    async def wrapper(request: web.Request):
        token = _extract_token(request)
        if not token:
            raise web.HTTPUnauthorized(reason="Missing token")
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                raise web.HTTPUnauthorized(reason="Invalid token type")
            request["user"] = payload
        except jwt.ExpiredSignatureError:
            raise web.HTTPUnauthorized(reason="Token expired")
        except jwt.InvalidTokenError:
            raise web.HTTPUnauthorized(reason="Invalid token")
        return await handler(request)
    return wrapper


def require_admin(handler):
    """Require admin role (stacks on top of require_auth)."""
    @wraps(handler)
    @require_auth
    async def wrapper(request: web.Request):
        if request["user"].get("role") != "admin":
            raise web.HTTPForbidden(reason="Admin access required")
        return await handler(request)
    return wrapper


# ── Rate limiter (in-memory sliding window) ────────────────

from collections import defaultdict, deque
import time

_rate_store: dict[str, deque] = defaultdict(deque)


def rate_limit(handler):
    """Sliding-window rate limiter per IP."""
    @wraps(handler)
    async def wrapper(request: web.Request):
        ip  = request.remote
        now = time.monotonic()
        dq  = _rate_store[ip]
        cutoff = now - Config.RATE_LIMIT_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= Config.RATE_LIMIT_REQUESTS:
            raise web.HTTPTooManyRequests(reason="Rate limit exceeded")
        dq.append(now)
        return await handler(request)
    return wrapper
