"""
backend/main.py
Application entry point — starts WebSocket + REST API concurrently.

Usage:
    python -m backend.main
"""
import asyncio
import logging

import backend.logger_setup  # noqa: F401 — must be first
from backend.config import Config
from backend.db.database import init_pool, close_pool
from backend.websocket_server import start_server as start_ws
from backend.api.routes import create_app

from aiohttp import web

logger = logging.getLogger(__name__)


async def start_api() -> None:
    app    = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, Config.API_HOST, Config.API_PORT)
    await site.start()
    logger.info("REST API running on http://%s:%d", Config.API_HOST, Config.API_PORT)


async def main() -> None:
    logger.info("=== CyberSec Dashboard Backend Starting ===")
    await init_pool()

    try:
        await asyncio.gather(
            start_ws(),
            start_api(),
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down...")
    finally:
        await close_pool()
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
