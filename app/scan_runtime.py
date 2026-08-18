"""Shared configured-client and memory-only query execution for interactive scans."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.alerts import fanout_watchlisted_findings
from app.config import Settings
from app.ingest import SQLAlchemyIngestRepository
from app.leakcheck import LeakCheckClient
from app.models import Scan, ScanStatus, Subject
from app.normalization import NormalizedSubject
from app.notifications import enqueue_new_findings
from app.platform_settings import PlatformSettingError, PlatformSettingsStore, SettingKey
from app.scans import run_scan

_CLIENT_KEYS = frozenset(
    {
        SettingKey.LEAKCHECK_API_KEY,
        SettingKey.LEAKCHECK_RPS,
        SettingKey.LEAKCHECK_CONCURRENCY,
        SettingKey.LEAKCHECK_MAX_RESPONSE_BYTES,
    }
)
logger = logging.getLogger(__name__)


async def configured_client(request: Request, db: AsyncSession) -> LeakCheckClient:
    """Return a process-shared client refreshed whenever encrypted settings change."""

    store = cast(PlatformSettingsStore, request.app.state.platform_settings)
    values = await store.read_many(db, _CLIENT_KEYS)
    digest = _client_config_digest(values)
    async with request.app.state.leakcheck_client_lock:
        cached = request.app.state.leakcheck_client
        if (
            isinstance(cached, LeakCheckClient)
            and request.app.state.leakcheck_client_config_digest == digest
        ):
            return cached
        client = client_from_platform_values(values)
        request.app.state.leakcheck_client = client
        request.app.state.leakcheck_client_config_digest = digest
        return client


async def execute_scan(
    session_factory: async_sessionmaker[AsyncSession],
    client: LeakCheckClient,
    settings: Settings,
    scan_id: uuid.UUID,
    subject_id: uuid.UUID,
    query: str,
) -> None:
    """Run after the response; the clear query exists only in this task's memory."""

    async with session_factory() as db:
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        subject_result = await db.execute(select(Subject).where(Subject.id == subject_id))
        scan = scan_result.scalar_one_or_none()
        subject = subject_result.scalar_one_or_none()
        if scan is None or subject is None:
            return
        started_at = datetime.now(UTC)
        scan.status = ScanStatus.RUNNING
        scan.started_at = started_at
        if subject.first_scanned_at is None:
            subject.first_scanned_at = started_at
        await db.commit()
        try:
            summary = await run_scan(
                client,
                SQLAlchemyIngestRepository(db),
                settings,
                scan=scan,
                subject=subject,
                query=query,
            )
            try:
                async with db.begin_nested():
                    await enqueue_new_findings(
                        db, subject=subject, finding_ids=summary.new_finding_ids
                    )
                    await fanout_watchlisted_findings(
                        db, subject=subject, finding_ids=summary.new_finding_ids
                    )
            except Exception:
                # Outbox/schema failures must never roll back or misreport a completed scan.
                logger.warning("post-scan fan-out could not be queued")
        except Exception as exc:
            await db.rollback()
            failed_scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
            failed_subject_result = await db.execute(
                select(Subject).where(Subject.id == subject_id)
            )
            failed_scan = failed_scan_result.scalar_one_or_none()
            failed_subject = failed_subject_result.scalar_one_or_none()
            failed_at = datetime.now(UTC)
            if failed_scan is not None:
                failed_scan.status = ScanStatus.FAILED
                failed_scan.finished_at = failed_at
                failed_scan.error = type(exc).__name__
            if failed_subject is not None:
                failed_subject.last_scanned_at = failed_at
            await db.commit()
            return
        await db.commit()


async def resolve_subject(
    db: AsyncSession,
    normalized: NormalizedSubject,
    *,
    linked_user_id: uuid.UUID | None = None,
) -> Subject:
    """Upsert a normalized subject, optionally binding its matching portal user."""

    statement = postgresql_insert(Subject).values(
        id=uuid.uuid4(),
        kind=normalized.kind,
        value_norm=normalized.value_norm,
        value_display=normalized.value_display,
        linked_user_id=linked_user_id,
    )
    query: Any = statement.on_conflict_do_update(
        constraint="uq_subjects_kind_value_norm",
        set_={
            "value_display": statement.excluded.value_display,
            "linked_user_id": (
                statement.excluded.linked_user_id
                if linked_user_id is not None
                else Subject.linked_user_id
            ),
        },
    ).returning(Subject)
    result = await db.execute(query)
    return cast(Subject, result.scalar_one())


def actor_scan_lock(actor_id: uuid.UUID) -> int:
    """Derive a stable signed advisory-lock key without exposing the actor UUID."""

    return int.from_bytes(
        hashlib.sha256(b"leakcheck/interactive-scan/v1\x00" + actor_id.bytes).digest()[:8],
        "big",
        signed=True,
    )


def client_from_platform_values(values: dict[SettingKey, str]) -> LeakCheckClient:
    """Construct the same bounded client for web and standalone worker processes."""

    return LeakCheckClient(
        values.get(SettingKey.LEAKCHECK_API_KEY, ""),
        requests_per_second=_setting_int(
            values, SettingKey.LEAKCHECK_RPS, 3, minimum=1, maximum=20
        ),
        concurrency=_setting_int(
            values, SettingKey.LEAKCHECK_CONCURRENCY, 3, minimum=1, maximum=50
        ),
        max_response_bytes=_setting_int(
            values,
            SettingKey.LEAKCHECK_MAX_RESPONSE_BYTES,
            32 * 1024 * 1024,
            minimum=1024,
            maximum=128 * 1024 * 1024,
        ),
    )


def _setting_int(
    values: dict[SettingKey, str],
    key: SettingKey,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = values.get(key)
    value = default if raw is None else int(raw)
    if not minimum <= value <= maximum:
        raise PlatformSettingError(f"invalid stored setting {key.value}")
    return value


def _client_config_digest(values: dict[SettingKey, str]) -> bytes:
    digest = hashlib.sha256()
    for key in sorted(_CLIENT_KEYS, key=lambda item: item.value):
        encoded = values.get(key, "").encode("utf-8")
        digest.update(key.value.encode("ascii"))
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()
