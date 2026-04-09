"""
backend/ai/geoip.py
GeoIP intelligence with caching (DB + in-memory LRU).
Uses ip-api.com (free, no key required for basic fields).
"""
import asyncio
import logging
from functools import lru_cache
from datetime import datetime, timedelta

import aiohttp

from backend.db import database as db

logger = logging.getLogger(__name__)

IP_API_URL  = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon,query"
CACHE_TTL   = timedelta(hours=24)

# In-memory LRU for hot IPs (avoids DB round-trip)
_mem_cache: dict[str, dict] = {}
_MEM_MAX = 500


async def lookup(ip: str) -> dict:
    """
    Return geo info dict for an IP.
    Priority: memory cache → DB cache → live API call.
    """
    # 1. Memory cache
    if ip in _mem_cache:
        return _mem_cache[ip]

    # 2. DB cache
    row = await db.fetchone(
        "SELECT * FROM ip_reputation WHERE ip_address = %s", (ip,)
    )
    if row and row.get("cached_at"):
        age = datetime.utcnow() - row["cached_at"]
        if age < CACHE_TTL:
            info = _row_to_info(row)
            _store_mem(ip, info)
            return info

    # 3. Live API
    info = await _fetch_api(ip)
    await _upsert_db(ip, info)
    _store_mem(ip, info)
    return info


async def _fetch_api(ip: str) -> dict:
    """Call ip-api.com. Returns safe defaults on failure."""
    defaults = {
        "country": "Unknown", "country_code": "XX",
        "city": "Unknown", "isp": "Unknown",
        "latitude": 0.0, "longitude": 0.0,
    }
    # Skip private / loopback IPs
    if _is_private(ip):
        return {**defaults, "country": "Private", "country_code": "LO"}

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as session:
            async with session.get(IP_API_URL.format(ip=ip)) as resp:
                if resp.status != 200:
                    return defaults
                data = await resp.json()
                if data.get("status") != "success":
                    return defaults
                return {
                    "country":      data.get("country",     "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "city":         data.get("city",        "Unknown"),
                    "isp":          data.get("isp",         "Unknown"),
                    "latitude":     float(data.get("lat", 0)),
                    "longitude":    float(data.get("lon", 0)),
                }
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
        return defaults


async def _upsert_db(ip: str, info: dict) -> None:
    try:
        await db.execute(
            """
            INSERT INTO ip_reputation
              (ip_address, country, city, isp, latitude, longitude, cached_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
              country=VALUES(country), city=VALUES(city), isp=VALUES(isp),
              latitude=VALUES(latitude), longitude=VALUES(longitude),
              cached_at=NOW()
            """,
            (ip, info["country"], info["city"], info["isp"],
             info["latitude"], info["longitude"]),
        )
    except Exception as exc:
        logger.debug("GeoIP DB upsert failed: %s", exc)


def _row_to_info(row: dict) -> dict:
    return {
        "country":      row.get("country",   "Unknown"),
        "country_code": "XX",
        "city":         row.get("city",      "Unknown"),
        "isp":          row.get("isp",       "Unknown"),
        "latitude":     float(row.get("latitude",  0) or 0),
        "longitude":    float(row.get("longitude", 0) or 0),
    }


def _store_mem(ip: str, info: dict) -> None:
    if len(_mem_cache) >= _MEM_MAX:
        # evict oldest key
        oldest = next(iter(_mem_cache))
        del _mem_cache[oldest]
    _mem_cache[ip] = info


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
        )
    except ValueError:
        return False


# Country → flag emoji helper
_FLAG_OFFSET = 127397
def country_flag(code: str) -> str:
    try:
        return "".join(chr(_FLAG_OFFSET + ord(c)) for c in code.upper()[:2])
    except Exception:
        return "🌐"
