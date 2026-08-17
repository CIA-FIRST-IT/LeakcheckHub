"""Finding remediation transition tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.models import Finding, FindingEvent, FindingEventType, FindingSeverity
from app.remediation import FindingNotFoundError, remediate_finding, unremediate_finding

NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)


@dataclass
class FakeResult:
    finding: Finding | None

    def scalar_one_or_none(self) -> Finding | None:
        return self.finding


@dataclass
class FakeDB:
    finding: Finding | None
    added: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    async def execute(self, statement: object) -> FakeResult:
        assert "FOR UPDATE" in str(statement)
        return FakeResult(self.finding)

    def add(self, value: object) -> None:
        self.added.append(value)


def make_finding() -> Finding:
    return Finding(
        id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        source_id=uuid.uuid4(),
        fingerprint=b"f" * 32,
        severity=FindingSeverity.MEDIUM,
        fields=[],
        raw={},
        first_seen_at=NOW,
        last_seen_at=NOW,
    )


@pytest.mark.anyio
async def test_remediate_and_unremediate_append_exactly_one_event_per_transition() -> None:
    finding = make_finding()
    db = FakeDB(finding)
    actor_id = uuid.uuid4()

    await remediate_finding(
        db,  # type: ignore[arg-type]
        finding_id=finding.id,
        actor_id=actor_id,
        note="Password rotated",
        now=NOW,
    )
    await remediate_finding(
        db,  # type: ignore[arg-type]
        finding_id=finding.id,
        actor_id=actor_id,
        note="Ignored duplicate",
        now=NOW,
    )

    assert finding.remediated_at == NOW
    assert finding.remediation_note == "Password rotated"
    assert len(db.added) == 1
    assert isinstance(db.added[0], FindingEvent)
    assert db.added[0].event is FindingEventType.REMEDIATED

    await unremediate_finding(
        db,  # type: ignore[arg-type]
        finding_id=finding.id,
        actor_id=actor_id,
        now=NOW,
    )
    await unremediate_finding(
        db,  # type: ignore[arg-type]
        finding_id=finding.id,
        actor_id=actor_id,
        now=NOW,
    )

    assert finding.remediated_at is None
    assert finding.remediation_note is None
    assert len(db.added) == 2
    assert isinstance(db.added[1], FindingEvent)
    assert db.added[1].event is FindingEventType.UNREMEDIATED


@pytest.mark.anyio
async def test_missing_finding_fails_closed() -> None:
    with pytest.raises(FindingNotFoundError):
        await remediate_finding(
            FakeDB(None),  # type: ignore[arg-type]
            finding_id=uuid.uuid4(),
            actor_id=uuid.uuid4(),
            note=None,
            now=NOW,
        )
