"""Configurable finding retention.

Nothing is deleted unless a super-admin chooses a policy. The default is to keep everything, so an
unconfigured deployment never loses evidence by surprise.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, FindingEvent
from app.platform_settings import PlatformSettingsStore, SettingKey

logger = logging.getLogger(__name__)

RETENTION_KEYS = frozenset({SettingKey.RETENTION_MODE, SettingKey.RETENTION_DAYS})

MODE_INDEFINITE = "indefinite"
MODE_NONE = "none"
MODE_DAYS = "days"


@dataclass(frozen=True)
class RetentionPolicy:
    """How long remediated findings are kept before deletion."""

    mode: str = MODE_INDEFINITE
    days: int | None = None

    @property
    def deletes_anything(self) -> bool:
        return self.mode in {MODE_NONE, MODE_DAYS}

    def cutoff(self, *, now: datetime) -> datetime:
        """The instant before which remediated findings are eligible for deletion."""

        if self.mode == MODE_NONE:
            return now
        if self.mode == MODE_DAYS and self.days is not None:
            return now - timedelta(days=self.days)
        raise ValueError("an indefinite policy has no cutoff")

    def describe(self) -> str:
        if self.mode == MODE_NONE:
            return "Remediated findings are deleted as soon as they are closed."
        if self.mode == MODE_DAYS and self.days is not None:
            return f"Remediated findings are deleted {self.days} days after remediation."
        return "Findings are kept indefinitely. Nothing is deleted automatically."


async def load_policy(db: AsyncSession, store: PlatformSettingsStore) -> RetentionPolicy:
    """Read the configured policy, falling back to keeping everything."""

    values = await store.read_many(db, RETENTION_KEYS)
    mode = (values.get(SettingKey.RETENTION_MODE) or MODE_INDEFINITE).strip()
    if mode not in {MODE_INDEFINITE, MODE_NONE, MODE_DAYS}:
        logger.warning("unknown retention mode %r; keeping everything", mode)
        return RetentionPolicy()
    raw_days = values.get(SettingKey.RETENTION_DAYS)
    days: int | None = None
    if raw_days is not None:
        try:
            days = int(raw_days)
        except ValueError:
            logger.warning("unreadable retention_days %r; keeping everything", raw_days)
            return RetentionPolicy()
    if mode == MODE_DAYS and (days is None or days < 1):
        logger.warning("retention_days is missing for a day-based policy; keeping everything")
        return RetentionPolicy()
    return RetentionPolicy(mode=mode, days=days)


async def purge_expired_findings(
    db: AsyncSession,
    store: PlatformSettingsStore,
    *,
    now: datetime | None = None,
    limit: int = 500,
) -> int:
    """Delete remediated findings past the configured cutoff, newest work first, in bounded batches.

    Only remediated findings are eligible: an open exposure is never deleted out from under an
    analyst regardless of age.
    """

    policy = await load_policy(db, store)
    if not policy.deletes_anything:
        return 0
    current = now or datetime.now(UTC)
    cutoff = policy.cutoff(now=current)

    eligible = await db.execute(
        select(Finding.id)
        .where(Finding.remediated_at.is_not(None), Finding.remediated_at <= cutoff)
        .limit(limit)
    )
    ids = list(eligible.scalars().all())
    if not ids:
        return 0
    # The event trail references the finding, so it must go first.
    await db.execute(delete(FindingEvent).where(FindingEvent.finding_id.in_(ids)))
    await db.execute(delete(Finding).where(Finding.id.in_(ids)))
    await db.flush()
    logger.info("retention purged %d findings older than %s", len(ids), cutoff.isoformat())
    return len(ids)
