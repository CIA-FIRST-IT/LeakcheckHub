"""Contract-neutral alert dedupe, fan-out, retry, and outage tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.alerts import dispatch_next_alert, enqueue_alert, fanout_watchlisted_findings
from app.models import (
    AlertOutbox,
    AlertOutboxStatus,
    AlertSinkName,
    Finding,
    FindingSeverity,
    Subject,
    SubjectKind,
    WatchlistEntry,
)


class _Result:
    def __init__(self, scalar: object = None, values: list[object] | None = None) -> None:
        self.scalar = scalar
        self.values = values or []

    def scalar_one_or_none(self) -> object:
        return self.scalar

    def scalars(self) -> _Result:
        return self

    def first(self) -> object:
        return self.values[0] if self.values else None

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.values)


class _DB:
    def __init__(self, results: list[_Result] | None = None) -> None:
        self.results = list(results or [])
        self.statements: list[object] = []
        self.commits = 0

    async def execute(self, statement: object) -> _Result:
        self.statements.append(statement)
        return self.results.pop(0) if self.results else _Result()

    async def commit(self) -> None:
        self.commits += 1


class _Sink:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.payloads: list[dict[str, object]] = []

    async def send(self, payload: dict[str, object]) -> None:
        self.payloads.append(payload)
        if self.error is not None:
            raise self.error


def _alert(*, attempts: int = 0) -> AlertOutbox:
    return AlertOutbox(
        id=uuid.uuid4(),
        sink=AlertSinkName.WAZUH,
        payload={"schema": "leakcheck.alert.v1", "event": "test"},
        status=AlertOutboxStatus.PENDING,
        dedupe_key=b"a" * 32,
        attempts=attempts,
        next_attempt_at=datetime(2026, 8, 17, tzinfo=UTC),
    )


@pytest.mark.anyio
async def test_dispatch_success_marks_delivered() -> None:
    alert = _alert()
    db = _DB([_Result(scalar=alert)])
    sink = _Sink()
    assert await dispatch_next_alert(
        db,
        {AlertSinkName.WAZUH: sink},
        now=datetime(2026, 8, 17, tzinfo=UTC),  # type: ignore[arg-type]
    )
    assert alert.status is AlertOutboxStatus.DELIVERED
    assert alert.attempts == 1
    assert sink.payloads == [alert.payload]
    assert db.commits == 1


@pytest.mark.anyio
async def test_total_outage_dead_letters_after_bounded_attempts_without_error_detail() -> None:
    alert = _alert(attempts=4)
    db = _DB([_Result(scalar=alert)])
    sink = _Sink(RuntimeError("secret upstream response body"))
    assert await dispatch_next_alert(
        db,
        {AlertSinkName.WAZUH: sink},
        now=datetime(2026, 8, 17, tzinfo=UTC),  # type: ignore[arg-type]
    )
    assert alert.status is AlertOutboxStatus.DEAD_LETTER
    assert alert.attempts == 5
    assert alert.last_error == "RuntimeError"
    assert "secret" not in alert.last_error


@pytest.mark.anyio
async def test_enqueue_is_database_deduplicated_per_sink_and_scope() -> None:
    db = _DB()
    payload = {"schema": "leakcheck.alert.v1", "event": "new_finding"}
    await enqueue_alert(
        db,
        sink=AlertSinkName.DFIR_IRIS,
        payload=payload,
        dedupe_scope="finding:event",  # type: ignore[arg-type]
    )
    await enqueue_alert(
        db,
        sink=AlertSinkName.DFIR_IRIS,
        payload=payload,
        dedupe_scope="finding:event",  # type: ignore[arg-type]
    )
    sql = [str(statement) for statement in db.statements]
    assert len(sql) == 2
    assert all("ON CONFLICT" in statement for statement in sql)


@pytest.mark.anyio
async def test_watchlist_fanout_envelope_excludes_finding_secrets() -> None:
    subject = Subject(
        id=uuid.uuid4(),
        kind=SubjectKind.EMAIL,
        value_norm="vip@example.com",
        value_display="vip@example.com",
    )
    finding = Finding(
        id=uuid.uuid4(),
        subject_id=subject.id,
        source_id=uuid.uuid4(),
        fields=[],
        raw={"password": "must-not-copy"},
        fingerprint=b"f" * 32,
        severity=FindingSeverity.HIGH,
        last_seen_at=datetime(2026, 8, 17, tzinfo=UTC),
    )
    entry = WatchlistEntry(
        id=uuid.uuid4(),
        subject_id=subject.id,
        user_id=None,
        alert_soc=False,
        alert_user=False,
        alert_wazuh=True,
        alert_iris=False,
        enabled=True,
        created_by=uuid.uuid4(),
    )
    second_entry = WatchlistEntry(
        id=uuid.uuid4(),
        subject_id=subject.id,
        user_id=None,
        alert_soc=False,
        alert_user=False,
        alert_wazuh=False,
        alert_iris=True,
        enabled=True,
        created_by=uuid.uuid4(),
    )
    db = _DB([_Result(values=[entry, second_entry]), _Result(values=[finding])])
    assert (
        await fanout_watchlisted_findings(
            db,
            subject=subject,
            finding_ids=(finding.id,),  # type: ignore[arg-type]
        )
        == 2
    )
    inserts = db.statements[2:]
    payloads = [statement.compile().params["payload"] for statement in inserts]  # type: ignore[attr-defined]
    assert all(payload["event"] == "re_leaked" for payload in payloads)
    assert all("password" not in payload for payload in payloads)
    assert all("raw" not in payload for payload in payloads)
