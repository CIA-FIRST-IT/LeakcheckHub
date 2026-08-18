"""Single-subject scan orchestration with quota and ingest accounting."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from app.config import Settings
from app.ingest import IngestRepository, IngestSummary, ingest_records
from app.leakcheck import QueryResult, QueryType
from app.models import Scan, ScanStatus, Subject


class QueryClient(Protocol):
    async def query(self, query_type: QueryType, query: str) -> QueryResult: ...


async def run_scan(
    client: QueryClient,
    repository: IngestRepository,
    settings: Settings,
    *,
    scan: Scan,
    subject: Subject,
    query: str,
    now: datetime | None = None,
) -> IngestSummary:
    """Query, ingest, and finalize a scan without persisting its cleartext query."""

    started_at = _utc_now(now)
    scan.status = ScanStatus.RUNNING
    scan.started_at = started_at
    if subject.first_scanned_at is None:
        subject.first_scanned_at = started_at
    try:
        result = await client.query(QueryType(subject.kind.value), query)
        summary = await ingest_records(
            repository,
            settings,
            subject=subject,
            records=result.records,
            actor_id=scan.requested_by,
            now=started_at,
        )
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.finished_at = started_at
        scan.error = type(exc).__name__
        subject.last_scanned_at = started_at
        raise
    complete_scan(scan, subject, result=result, summary=summary, at=started_at)
    return summary


def complete_scan(
    scan: Scan,
    subject: Subject,
    *,
    result: QueryResult,
    summary: IngestSummary,
    at: datetime,
) -> None:
    """Persist every vendor quota observation, including its documented one-request lag."""

    scan.status = ScanStatus.SUCCEEDED
    scan.finished_at = at
    scan.result_count = len(result.records)
    scan.new_count = summary.new_count
    scan.quota = result.quota
    scan.truncated = result.truncated
    scan.error = None
    subject.last_scanned_at = at


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("scan timestamps must be timezone-aware")
    return current.astimezone(UTC)
