"""Standalone, resumable batch queue worker."""

from __future__ import annotations

import asyncio
import logging
import socket
import uuid

from sqlalchemy import select

from app.batches import claim_next, finish_work
from app.config import get_settings
from app.db import get_async_session_factory
from app.models import Scan, ScanStatus, ScanTrigger
from app.platform_settings import PlatformSettingsStore, SettingKey
from app.scan_runtime import client_from_platform_values, execute_scan
from app.scheduling import dispatch_due_schedules

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
_CLIENT_KEYS = frozenset(
    {
        SettingKey.LEAKCHECK_API_KEY,
        SettingKey.LEAKCHECK_RPS,
        SettingKey.LEAKCHECK_CONCURRENCY,
        SettingKey.LEAKCHECK_MAX_RESPONSE_BYTES,
    }
)


async def run() -> None:
    """Drain durable work forever, safely sharing a queue with other worker processes."""

    settings = get_settings()
    sessions = get_async_session_factory()
    store = PlatformSettingsStore(settings)
    worker_id = f"{socket.gethostname()}:{uuid.uuid4()}"
    client = None
    try:
        while True:
            async with sessions() as db:
                await dispatch_due_schedules(db)
            async with sessions() as db:
                work = await claim_next(db, worker_id)
            if work is None:
                await asyncio.sleep(1)
                continue
            if client is None:
                async with sessions() as db:
                    client = client_from_platform_values(await store.read_many(db, _CLIENT_KEYS))
            scan_id = uuid.uuid4()
            async with sessions() as db:
                db.add(
                    Scan(
                        id=scan_id,
                        subject_id=work.subject_id,
                        requested_by=None,
                        trigger=ScanTrigger.BATCH,
                        status=ScanStatus.PENDING,
                    )
                )
                await db.commit()
            await execute_scan(sessions, client, settings, scan_id, work.subject_id, work.query)
            async with sessions() as db:
                scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                await finish_work(
                    db,
                    work,
                    succeeded=scan.status is ScanStatus.SUCCEEDED,
                    error=scan.error,
                )
    finally:
        logger.info("worker stopped")


def main() -> None:
    get_settings()
    asyncio.run(run())


if __name__ == "__main__":
    main()
