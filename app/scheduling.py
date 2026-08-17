"""PostgreSQL-backed recurring batch dispatch using APScheduler cron semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.batches import create_batch
from app.models import BatchTarget, Schedule, ScheduleKind
from app.notifications import enqueue_digest_notifications

_LEADER_LOCK_ID = 5_114_293_001


class ScheduleValidationError(ValueError):
    """A cron expression, timezone, or target is invalid."""


def next_fire_time(cron: str, timezone: str, *, now: datetime | None = None) -> datetime:
    """Validate a standard five-field cron and return its next UTC occurrence."""

    try:
        zone = ZoneInfo(timezone)
        trigger = CronTrigger.from_crontab(cron, timezone=zone)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise ScheduleValidationError("invalid cron expression or timezone") from exc
    # CronTrigger treats an exact boundary as eligible; schedules must always advance beyond "now".
    reference = (now or datetime.now(UTC)) + timedelta(microseconds=1)
    next_run = trigger.get_next_fire_time(None, reference)
    if next_run is None:
        raise ScheduleValidationError("schedule has no future occurrence")
    return cast(datetime, next_run.astimezone(UTC))


async def dispatch_due_schedules(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Dispatch one leader tick; a transaction advisory lock excludes every peer worker."""

    tick = now or datetime.now(UTC)
    leader = await db.scalar(select(func.pg_try_advisory_xact_lock(_LEADER_LOCK_ID)))
    if leader is not True:
        await db.rollback()
        return 0
    result = await db.execute(
        select(Schedule)
        .where(Schedule.enabled.is_(True), Schedule.next_run_at <= tick)
        .order_by(Schedule.next_run_at, Schedule.id)
        .with_for_update(skip_locked=True)
    )
    dispatched = 0
    for schedule in result.scalars():
        scheduled_for = schedule.next_run_at
        schedule.next_run_at = next_fire_time(schedule.cron, schedule.timezone, now=tick)
        if tick - scheduled_for > timedelta(seconds=schedule.misfire_grace_seconds):
            schedule.last_error = "misfire grace exceeded"
            continue
        try:
            if schedule.kind is ScheduleKind.DIGEST:
                await enqueue_digest_notifications(db, now=tick)
            else:
                target_type = (
                    BatchTarget.OU if schedule.kind is ScheduleKind.SCAN_OU else BatchTarget.DOMAIN
                )
                await create_batch(
                    db,
                    actor_id=schedule.created_by,
                    target_type=target_type,
                    target_value=schedule.target,
                )
        except ValueError as exc:
            schedule.last_error = str(exc)[:255]
        else:
            schedule.last_run_at = tick
            schedule.last_error = None
            dispatched += 1
    await db.commit()
    return dispatched
