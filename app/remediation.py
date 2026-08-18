"""Transactional finding remediation state transitions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, FindingEvent, FindingEventType


class FindingNotFoundError(Exception):
    """No finding exists for the supplied identifier."""


async def remediate_finding(
    db: AsyncSession,
    *,
    finding_id: uuid.UUID,
    actor_id: uuid.UUID,
    note: str | None,
    now: datetime | None = None,
) -> Finding:
    """Mark a finding remediated once and append the corresponding event."""

    finding = await _locked_finding(db, finding_id)
    if finding.remediated_at is not None:
        return finding
    at = _utc_now(now)
    finding.remediated_at = at
    finding.remediated_by = actor_id
    finding.remediation_note = note
    _add_event(db, finding.id, FindingEventType.REMEDIATED, actor_id=actor_id, at=at)
    await db.flush()
    return finding


async def unremediate_finding(
    db: AsyncSession,
    *,
    finding_id: uuid.UUID,
    actor_id: uuid.UUID,
    now: datetime | None = None,
) -> Finding:
    """Reopen a remediated finding and retain an append-only transition event."""

    finding = await _locked_finding(db, finding_id)
    if finding.remediated_at is None:
        return finding
    at = _utc_now(now)
    finding.remediated_at = None
    finding.remediated_by = None
    finding.remediation_note = None
    _add_event(db, finding.id, FindingEventType.UNREMEDIATED, actor_id=actor_id, at=at)
    await db.flush()
    return finding


async def _locked_finding(db: AsyncSession, finding_id: uuid.UUID) -> Finding:
    result = await db.execute(select(Finding).where(Finding.id == finding_id).with_for_update())
    finding = result.scalar_one_or_none()
    if finding is None:
        raise FindingNotFoundError
    return finding


def _add_event(
    db: AsyncSession,
    finding_id: uuid.UUID,
    event: FindingEventType,
    *,
    actor_id: uuid.UUID,
    at: datetime,
) -> None:
    db.add(
        FindingEvent(
            id=uuid.uuid4(),
            finding_id=finding_id,
            event=event,
            actor_id=actor_id,
            at=at,
            meta={},
        )
    )


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("remediation timestamps must be timezone-aware")
    return current.astimezone(UTC)
