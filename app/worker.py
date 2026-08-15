"""Worker process placeholder; queue processing is introduced in M6."""

from __future__ import annotations

import asyncio
import logging

from app.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run() -> None:
    """Keep the worker alive until the scan queue is implemented."""

    logger.info("worker started; no queue handlers are registered yet")
    await asyncio.Event().wait()


def main() -> None:
    # Trigger the same fail-fast configuration validation as the web entrypoint.
    get_settings()
    asyncio.run(run())


if __name__ == "__main__":
    main()
