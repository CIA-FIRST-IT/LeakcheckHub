"""Scan orchestration tests, including mandatory quota observation persistence."""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from app.config import Settings
from app.ingest import IngestSummary
from app.leakcheck import QueryResult, QueryType
from app.models import Scan, ScanStatus, ScanTrigger, Subject, SubjectKind
from app.scans import complete_scan, run_scan

NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )


def make_scan(subject: Subject) -> Scan:
    return Scan(
        id=uuid.uuid4(),
        subject_id=subject.id,
        requested_by=uuid.uuid4(),
        trigger=ScanTrigger.MANUAL,
        status=ScanStatus.PENDING,
        result_count=0,
        new_count=0,
        truncated=False,
    )


def make_subject() -> Subject:
    return Subject(
        id=uuid.uuid4(),
        kind=SubjectKind.EMAIL,
        value_norm="person@example.test",
        value_display="person@example.test",
    )


def test_complete_scan_records_lagging_quota_without_using_it_as_a_gate() -> None:
    subject = make_subject()
    scan = make_scan(subject)
    result = QueryResult(QueryType.EMAIL, (), quota=999_986, found=0)
    summary = IngestSummary((), new_count=0, re_leaked_count=0)

    complete_scan(scan, subject, result=result, summary=summary, at=NOW)

    assert scan.status is ScanStatus.SUCCEEDED
    assert scan.quota == 999_986
    assert scan.result_count == 0
    assert subject.last_scanned_at == NOW


@dataclass
class FailingClient:
    async def query(self, query_type: QueryType, query: str) -> QueryResult:
        del query_type, query
        raise RuntimeError("vendor response must not be persisted")


@pytest.mark.anyio
async def test_failed_scan_records_only_the_error_class_not_query_or_vendor_detail() -> None:
    subject = make_subject()
    scan = make_scan(subject)

    with pytest.raises(RuntimeError):
        await run_scan(
            FailingClient(),
            object(),  # type: ignore[arg-type]
            make_settings(),
            scan=scan,
            subject=subject,
            query="secret-query-value",
            now=NOW,
        )

    assert scan.status is ScanStatus.FAILED
    assert scan.error == "RuntimeError"
    assert "secret-query-value" not in scan.error
