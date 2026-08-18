"""Contract-neutral SIEM alert outbox, retries, dead-lettering, and watchlist fan-out."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AlertOutbox,
    AlertOutboxStatus,
    AlertSinkName,
    Finding,
    FindingSeverity,
    Subject,
    WatchlistEntry,
)
from app.notifications import enqueue_notification

_MAX_ATTEMPTS = 5


class AlertSink(Protocol):
    """A verified sink adapter accepts the stable internal envelope only."""

    async def send(self, payload: Mapping[str, object]) -> None: ...


async def enqueue_alert(
    db: AsyncSession,
    *,
    sink: AlertSinkName,
    payload: dict[str, object],
    dedupe_scope: str,
) -> None:
    """Persist one alert per sink/event scope without knowing any remote API shape."""

    await db.execute(
        postgresql_insert(AlertOutbox)
        .values(
            id=uuid.uuid4(),
            sink=sink,
            payload=payload,
            dedupe_key=_dedupe_key(sink, dedupe_scope),
        )
        .on_conflict_do_nothing(constraint="uq_alert_outbox_dedupe_key")
    )


async def enqueue_test_alert(db: AsyncSession, sink: AlertSinkName) -> None:
    test_id = uuid.uuid4()
    await enqueue_alert(
        db,
        sink=sink,
        payload={
            "schema": "leakcheck.alert.v1",
            "event": "test",
            "test_id": str(test_id),
            "generated_at": datetime.now(UTC).isoformat(),
        },
        dedupe_scope=f"test:{test_id}",
    )


async def fanout_watchlisted_findings(
    db: AsyncSession,
    *,
    subject: Subject,
    finding_ids: tuple[uuid.UUID, ...],
) -> int:
    """Queue enabled generic channels for new/re-leaked findings; never serialize credentials."""

    if not finding_ids:
        return 0
    clauses = [WatchlistEntry.subject_id == subject.id]
    if subject.linked_user_id is not None:
        clauses.append(WatchlistEntry.user_id == subject.linked_user_id)
    watchlist_result = await db.execute(
        select(WatchlistEntry).where(WatchlistEntry.enabled.is_(True), or_(*clauses))
    )
    entries = tuple(watchlist_result.scalars())
    if not entries:
        return 0
    findings = tuple(
        (await db.execute(select(Finding).where(Finding.id.in_(finding_ids)))).scalars()
    )
    queued = 0
    for finding in findings:
        event = "re_leaked" if finding.severity is FindingSeverity.HIGH else "new_finding"
        payload: dict[str, object] = {
            "schema": "leakcheck.alert.v1",
            "event": event,
            "finding_id": str(finding.id),
            "subject_id": str(subject.id),
            "subject_kind": subject.kind.value,
            "subject_value": subject.value_norm,
            "observed_at": finding.last_seen_at.isoformat(),
        }
        for enabled, sink in (
            (any(entry.alert_wazuh for entry in entries), AlertSinkName.WAZUH),
            (any(entry.alert_iris for entry in entries), AlertSinkName.DFIR_IRIS),
        ):
            if enabled:
                await enqueue_alert(
                    db,
                    sink=sink,
                    payload=payload,
                    dedupe_scope=f"{finding.id}:{event}",
                )
                queued += 1
    if any(entry.alert_user for entry in entries) and subject.linked_user_id is not None:
        await enqueue_notification(db, user_id=subject.linked_user_id, finding_ids=finding_ids)
    return queued


async def dispatch_next_alert(
    db: AsyncSession,
    sinks: Mapping[AlertSinkName, AlertSink],
    *,
    now: datetime | None = None,
) -> bool:
    """Attempt one due alert, retaining safe failure type and bounded exponential retry state."""

    current = now or datetime.now(UTC)
    result = await db.execute(
        select(AlertOutbox)
        .where(
            AlertOutbox.status == AlertOutboxStatus.PENDING,
            AlertOutbox.next_attempt_at <= current,
        )
        .order_by(AlertOutbox.next_attempt_at, AlertOutbox.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        return False
    alert.attempts += 1
    try:
        sink = sinks.get(alert.sink)
        if sink is None:
            raise LookupError("sink adapter is not configured")
        await sink.send(alert.payload)
    except Exception as exc:
        alert.last_error = type(exc).__name__
        if alert.attempts >= _MAX_ATTEMPTS:
            alert.status = AlertOutboxStatus.DEAD_LETTER
        else:
            delay = min(15 * (2 ** (alert.attempts - 1)), 15 * 60)
            alert.next_attempt_at = current + timedelta(seconds=delay)
    else:
        alert.status = AlertOutboxStatus.DELIVERED
        alert.delivered_at = current
        alert.last_error = None
    await db.commit()
    return True


def _dedupe_key(sink: AlertSinkName, scope: str) -> bytes:
    return hashlib.sha256(
        b"leakcheck/alert-outbox/v1\x00"
        + sink.value.encode("ascii")
        + b"\x00"
        + scope.encode("ascii")
    ).digest()
