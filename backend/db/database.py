"""
backend/db/database.py
Async MySQL connection pool using aiomysql.
"""
import asyncio
import logging
import aiomysql
from backend.config import Config

logger = logging.getLogger(__name__)

_pool: aiomysql.Pool | None = None


async def init_pool() -> None:
    """Initialize the global connection pool. Call once at startup."""
    global _pool
    _pool = await aiomysql.create_pool(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        db=Config.DB_NAME,
        minsize=3,
        maxsize=15,
        autocommit=True,
        charset="utf8mb4",
        connect_timeout=10,
    )
    logger.info("MySQL connection pool initialised (min=3, max=15)")


async def close_pool() -> None:
    global _pool
    if _pool:
        _pool.close()
        await _pool.wait_closed()
        _pool = None


def get_pool() -> aiomysql.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised — call init_pool() first")
    return _pool


# ── Convenience helpers ────────────────────────────────────

async def fetchone(sql: str, args: tuple = ()) -> dict | None:
    async with get_pool().acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, args)
            return await cur.fetchone()


async def fetchall(sql: str, args: tuple = ()) -> list[dict]:
    async with get_pool().acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, args)
            return await cur.fetchall()


async def execute(sql: str, args: tuple = ()) -> int:
    """Execute INSERT/UPDATE/DELETE. Returns lastrowid."""
    async with get_pool().acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, args)
            return cur.lastrowid


async def executemany(sql: str, args_list: list[tuple]) -> None:
    async with get_pool().acquire() as conn:
        async with conn.cursor() as cur:
            await cur.executemany(sql, args_list)
