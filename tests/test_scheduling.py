"""Cron, leader election, and misfire behavior without wall-clock or database dependencies."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models import Schedule, ScheduleKind
from app.scheduling import ScheduleValidationError, dispatch_due_schedules, next_fire_time


def test_next_run_honors_iana_timezone_and_dst() -> None:
    # Midnight in New York is 04:00 UTC while daylight saving time is active.
    now = datetime(2026, 8, 17, 3, 0, tzinfo=UTC)
    assert next_fire_time("0 0 * * *", "America/New_York", now=now) == datetime(
        2026, 8, 17, 4, 0, tzinfo=UTC
    )


def test_invalid_cron_or_timezone_fails_closed() -> None:
    with pytest.raises(ScheduleValidationError):
        next_fire_time("not cron", "UTC")
    with pytest.raises(ScheduleValidationError):
        next_fire_time("0 2 * * *", "Mars/Olympus_Mons")


class _Scalars:
    def __init__(self, schedules: list[Schedule]) -> None:
        self._schedules = schedules

    def scalars(self) -> list[Schedule]:
        return self._schedules


class _ScheduleDB:
    def __init__(self, leader: bool, schedules: list[Schedule]) -> None:
        self.leader = leader
        self.schedules = schedules
        self.commits = 0
        self.rollbacks = 0

    async def scalar(self, _: object) -> bool:
        return self.leader

    async def execute(self, _: object) -> _Scalars:
        return _Scalars(self.schedules)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


@pytest.mark.anyio
async def test_only_advisory_lock_leader_dispatches() -> None:
    leader = _ScheduleDB(True, [])
    follower = _ScheduleDB(False, [])
    assert await dispatch_due_schedules(leader) == 0  # type: ignore[arg-type]
    assert await dispatch_due_schedules(follower) == 0  # type: ignore[arg-type]
    assert leader.commits == 1
    assert follower.commits == 0
    assert follower.rollbacks == 1


@pytest.mark.anyio
async def test_late_run_beyond_grace_is_skipped_and_advanced() -> None:
    now = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
    schedule = Schedule(
        id=uuid.uuid4(),
        kind=ScheduleKind.SCAN_DOMAIN,
        target="example.com",
        cron="0 * * * *",
        timezone="UTC",
        enabled=True,
        misfire_grace_seconds=60,
        next_run_at=now - timedelta(minutes=10),
        created_by=uuid.uuid4(),
    )
    db = _ScheduleDB(True, [schedule])
    assert await dispatch_due_schedules(db, now=now) == 0  # type: ignore[arg-type]
    assert schedule.last_error == "misfire grace exceeded"
    assert schedule.next_run_at == datetime(2026, 8, 17, 13, 0, tzinfo=UTC)
    assert db.commits == 1
