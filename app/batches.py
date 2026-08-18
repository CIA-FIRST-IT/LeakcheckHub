"""Durable batch construction and concurrent-safe queue claiming."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    BatchStatus,
    BatchTarget,
    QueueStatus,
    ScanBatch,
    ScanQueue,
    Subject,
    SubjectKind,
    User,
)

_STALE_AFTER = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class ClaimedWork:
    queue_id: uuid.UUID
    batch_id: uuid.UUID
    subject_id: uuid.UUID
    query: str


async def create_batch(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID,
    target_type: BatchTarget,
    target_value: str | tuple[uuid.UUID, ...],
) -> ScanBatch:
    """Resolve an OU/domain/selection into deduplicated email work without executing it."""

    users_query = select(User).where(User.is_active.is_(True))
    target: dict[str, object]
    if target_type is BatchTarget.OU:
        if not isinstance(target_value, str):
            raise ValueError("OU target must be a path")
        users_query = users_query.where(
            or_(User.ou_path == target_value, User.ou_path.like(_escaped_ou_prefix(target_value)))
        )
        target = {"ou_path": target_value}
    elif target_type is BatchTarget.DOMAIN:
        if not isinstance(target_value, str):
            raise ValueError("domain target must be text")
        domain = target_value.casefold().lstrip("@")
        users_query = users_query.where(User.email.ilike(f"%@{_escape_like(domain)}", escape="\\"))
        target = {"domain": domain}
    else:
        if not isinstance(target_value, tuple):
            raise ValueError("selection target must contain user IDs")
        users_query = users_query.where(User.id.in_(target_value))
        target = {"user_ids": [str(item) for item in target_value]}
    users = tuple((await db.execute(users_query.order_by(User.email))).scalars())
    if not users:
        raise ValueError("batch target matched no active users")
    batch = ScanBatch(
        id=uuid.uuid4(),
        target_type=target_type,
        target=target,
        status=BatchStatus.PENDING,
        created_by=actor_id,
        total_count=len(users),
    )
    db.add(batch)
    await db.flush()
    for user in users:
        subject_statement = postgresql_insert(Subject).values(
            id=uuid.uuid4(),
            kind=SubjectKind.EMAIL,
            value_norm=str(user.email).casefold(),
            value_display=str(user.email),
            linked_user_id=user.id,
        )
        subject_result = await db.execute(
            subject_statement.on_conflict_do_update(
                constraint="uq_subjects_kind_value_norm",
                set_={"linked_user_id": subject_statement.excluded.linked_user_id},
            ).returning(Subject.id)
        )
        subject_id = subject_result.scalar_one()
        await db.execute(
            postgresql_insert(ScanQueue)
            .values(id=uuid.uuid4(), batch_id=batch.id, subject_id=subject_id)
            .on_conflict_do_nothing(constraint="uq_scan_queue_batch_subject")
        )
    await db.flush()
    return batch


def claim_statement(worker_id: str, *, now: datetime | None = None) -> Any:
    """Build the atomic claim statement; SKIP LOCKED prevents duplicate concurrent work."""

    claimed_at = now or datetime.now(UTC)
    candidate = (
        select(ScanQueue.id)
        .where(
            or_(
                ScanQueue.status == QueueStatus.QUEUED,
                (ScanQueue.status == QueueStatus.RUNNING)
                & (ScanQueue.locked_at < claimed_at - _STALE_AFTER),
            )
        )
        .order_by(ScanQueue.created_at, ScanQueue.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    return (
        update(ScanQueue)
        .where(ScanQueue.id == candidate)
        .values(
            status=QueueStatus.RUNNING,
            locked_by=worker_id[:255],
            locked_at=claimed_at,
            attempts=ScanQueue.attempts + 1,
            last_error=None,
        )
        .returning(ScanQueue.id, ScanQueue.batch_id, ScanQueue.subject_id)
    )


async def claim_next(db: AsyncSession, worker_id: str) -> ClaimedWork | None:
    row = (await db.execute(claim_statement(worker_id))).one_or_none()
    if row is None:
        return None
    queue_id, batch_id, subject_id = row
    subject = (await db.execute(select(Subject).where(Subject.id == subject_id))).scalar_one()
    await db.execute(
        update(ScanBatch)
        .where(ScanBatch.id == batch_id, ScanBatch.status == BatchStatus.PENDING)
        .values(status=BatchStatus.RUNNING, started_at=func.now())
    )
    await db.commit()
    return ClaimedWork(queue_id, batch_id, subject_id, subject.value_norm)


async def finish_work(
    db: AsyncSession, work: ClaimedWork, *, succeeded: bool, error: str | None = None
) -> None:
    status = QueueStatus.SUCCEEDED if succeeded else QueueStatus.FAILED
    await db.execute(
        update(ScanQueue)
        .where(ScanQueue.id == work.queue_id, ScanQueue.status == QueueStatus.RUNNING)
        .values(
            status=status,
            finished_at=func.now(),
            locked_by=None,
            locked_at=None,
            last_error=None if succeeded else (error or "scan failed")[:255],
        )
    )
    counts = (
        await db.execute(
            select(
                func.count().filter(ScanQueue.status == QueueStatus.SUCCEEDED),
                func.count().filter(ScanQueue.status == QueueStatus.FAILED),
                func.count(),
            ).where(ScanQueue.batch_id == work.batch_id)
        )
    ).one()
    completed, failed, total = (int(item) for item in counts)
    values: dict[str, object] = {"completed_count": completed, "failed_count": failed}
    if completed + failed == total:
        values.update(
            status=(BatchStatus.SUCCEEDED if failed == 0 else BatchStatus.PARTIAL),
            finished_at=datetime.now(UTC),
        )
    await db.execute(update(ScanBatch).where(ScanBatch.id == work.batch_id).values(**values))
    await db.commit()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _escaped_ou_prefix(path: str) -> str:
    return _escape_like(path.rstrip("/") + "/") + "%"
