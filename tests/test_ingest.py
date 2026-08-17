"""End-to-end offline tests for idempotent ingest and re-leak behavior."""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

import pytest
from sqlalchemy.dialects import postgresql

from app.config import Settings
from app.ingest import (
    FindingDraft,
    SourceIdentity,
    SQLAlchemyIngestRepository,
    UpsertedFinding,
    ingest_records,
)
from app.leakcheck import BreachSource as VendorSource
from app.leakcheck import LeakRecord
from app.models import (
    BreachSource,
    Finding,
    FindingEventType,
    FindingSeverity,
    Subject,
    SubjectKind,
)
from app.normalization import normalize_subject
from app.remediation import remediate_finding

NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )


def make_subject() -> Subject:
    normalized = normalize_subject(SubjectKind.EMAIL, "bob@example.test")
    return Subject(
        id=uuid.uuid4(),
        kind=normalized.kind,
        value_norm=normalized.value_norm,
        value_display=normalized.value_display,
    )


def record(*, breach_date: str | None, password: str | None) -> LeakRecord:
    raw: dict[str, object] = {
        "email": "bob@example.test",
        "password": password,
        "source": {"name": "Canva", "breach_date": breach_date},
    }
    return LeakRecord(
        email="bob@example.test",
        username="bob",
        phone=None,
        origin=None,
        password=password,
        fields=("email", "username", "password"),
        source=VendorSource(
            name="Canva",
            breach_date=breach_date,
            unverified=False,
            passwordless=password is None,
            compilation=False,
        ),
        raw=raw,
    )


@dataclass
class MemoryRepository:
    sources: dict[tuple[str, date], BreachSource] = field(default_factory=dict)
    findings: dict[bytes, Finding] = field(default_factory=dict)
    events: list[tuple[uuid.UUID, FindingEventType, dict[str, object]]] = field(
        default_factory=list
    )

    async def resolve_source(self, source: SourceIdentity) -> BreachSource:
        key = (source.name_norm, source.breach_date_norm)
        if key not in self.sources:
            self.sources[key] = BreachSource(
                id=uuid.uuid4(),
                name=source.name,
                name_norm=source.name_norm,
                breach_date=source.breach_date,
                breach_date_norm=source.breach_date_norm,
                unverified=source.unverified,
                passwordless=source.passwordless,
                compilation=source.compilation,
                extra=source.extra,
            )
        return self.sources[key]

    async def upsert_finding(self, draft: FindingDraft) -> UpsertedFinding:
        existing = self.findings.get(draft.fingerprint)
        if existing is not None:
            existing.last_seen_at = draft.seen_at
            existing.raw = draft.raw
            return UpsertedFinding(existing, False)
        protected = draft.password
        finding = Finding(
            id=draft.id,
            subject_id=draft.subject_id,
            source_id=draft.source_id,
            email=draft.email,
            username=draft.username,
            phone=draft.phone,
            origin=draft.origin,
            identity_key=draft.identity_key,
            password_ciphertext=protected.ciphertext if protected else None,
            password_nonce=protected.nonce if protected else None,
            password_sha256=protected.sha256 if protected else None,
            password_mask=protected.mask if protected else None,
            password_len=protected.length if protected else None,
            password_charset=protected.charset if protected else None,
            fields=draft.fields,
            raw=draft.raw,
            fingerprint=draft.fingerprint,
            severity=FindingSeverity.MEDIUM,
            first_seen_at=draft.seen_at,
            last_seen_at=draft.seen_at,
        )
        self.findings[draft.fingerprint] = finding
        return UpsertedFinding(finding, True)

    async def find_remediated_predecessor(
        self, finding: Finding, source: SourceIdentity
    ) -> Finding | None:
        if source.name_norm == "unknown" or finding.identity_key is None:
            return None
        matching_source_ids = {
            item.id for item in self.sources.values() if item.name_norm == source.name_norm
        }
        return next(
            (
                candidate
                for candidate in self.findings.values()
                if candidate.id != finding.id
                and candidate.subject_id == finding.subject_id
                and candidate.source_id in matching_source_ids
                and candidate.identity_key == finding.identity_key
                and candidate.remediated_at is not None
                and candidate.superseded_by_id is None
                and candidate.password_sha256 != finding.password_sha256
            ),
            None,
        )

    async def link_releak(self, previous: Finding, current: Finding, *, at: datetime) -> None:
        del at
        previous.superseded_by_id = current.id
        current.severity = FindingSeverity.HIGH

    async def add_event(
        self,
        finding_id: uuid.UUID,
        event: FindingEventType,
        *,
        actor_id: uuid.UUID | None,
        at: datetime,
        meta: dict[str, object] | None = None,
    ) -> None:
        del actor_id, at
        self.events.append((finding_id, event, meta or {}))


@dataclass
class LockedFindingResult:
    finding: Finding

    def scalar_one_or_none(self) -> Finding:
        return self.finding


@dataclass
class RemediationDB:
    finding: Finding
    added: list[object] = field(default_factory=list)

    async def execute(self, statement: object) -> LockedFindingResult:
        assert "FOR UPDATE" in str(statement)
        return LockedFindingResult(self.finding)

    def add(self, value: object) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        return None


@pytest.mark.anyio
async def test_full_bob_canva_remediation_and_releak_scenario() -> None:
    repository = MemoryRepository()
    settings = make_settings()
    subject = make_subject()
    old_password = "old-password"  # noqa: S105 - synthetic fixture
    new_password = "new-password"  # noqa: S105 - synthetic fixture

    first = await ingest_records(
        repository,
        settings,
        subject=subject,
        records=[record(breach_date="2019-05-24", password=old_password)],
        now=NOW,
    )
    old_finding = first.findings[0]
    remediation_db = RemediationDB(old_finding)
    await remediate_finding(
        remediation_db,  # type: ignore[arg-type]
        finding_id=old_finding.id,
        actor_id=uuid.uuid4(),
        note="Rotated after the 2019 breach",
        now=NOW,
    )

    repeat = await ingest_records(
        repository,
        settings,
        subject=subject,
        records=[record(breach_date="2019-05-24", password=old_password)],
        now=NOW,
    )
    fresh = await ingest_records(
        repository,
        settings,
        subject=subject,
        records=[record(breach_date="2026-01-02", password=new_password)],
        now=NOW,
    )

    assert first.new_count == 1
    assert repeat.new_count == 0
    assert repeat.findings[0] is old_finding
    assert old_finding.remediated_at == NOW
    assert len(remediation_db.added) == 1
    assert fresh.new_count == 1
    assert fresh.re_leaked_count == 1
    new_finding = fresh.findings[0]
    assert new_finding.remediated_at is None
    assert new_finding.severity is FindingSeverity.HIGH
    assert old_finding.superseded_by_id == new_finding.id
    assert (new_finding.id, FindingEventType.RE_LEAKED) in [
        (finding_id, event) for finding_id, event, _ in repository.events
    ]


@pytest.mark.anyio
async def test_ingest_removes_cleartext_password_from_raw_and_is_idempotent() -> None:
    repository = MemoryRepository()
    password = "never-store-this"  # noqa: S105 - synthetic fixture
    leak_record = record(breach_date=None, password=password)
    leak_record.raw["nested"] = [{"password": password, "safe": "retained"}]
    result = await ingest_records(
        repository,
        make_settings(),
        subject=make_subject(),
        records=[leak_record],
        now=NOW,
    )
    finding = result.findings[0]

    assert "password" not in finding.raw
    assert password not in repr(finding.raw)
    assert finding.raw["nested"] == [{"safe": "retained"}]
    assert finding.password_ciphertext != password.encode()


@pytest.mark.anyio
async def test_passwordless_records_remain_distinct_across_breach_dates() -> None:
    repository = MemoryRepository()
    subject = make_subject()
    result = await ingest_records(
        repository,
        make_settings(),
        subject=subject,
        records=[
            record(breach_date="2019-01-01", password=None),
            record(breach_date="2026-01-01", password=None),
        ],
        now=NOW,
    )

    assert result.new_count == 2
    assert len(repository.findings) == 2
    assert all(finding.password_ciphertext is None for finding in result.findings)


@dataclass
class StatementResult:
    finding: Finding

    def one(self) -> tuple[Finding, bool]:
        return self.finding, True


@dataclass
class StatementDB:
    finding: Finding
    statement: object | None = None

    async def execute(self, statement: object) -> StatementResult:
        self.statement = statement
        return StatementResult(self.finding)


@pytest.mark.anyio
async def test_sql_repository_uses_atomic_fingerprint_conflict_upsert() -> None:
    finding = Finding(
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
    db = StatementDB(finding)
    draft = FindingDraft(
        id=finding.id,
        subject_id=finding.subject_id,
        source_id=finding.source_id,
        email="bob@example.test",
        username="bob",
        phone=None,
        origin=None,
        identity_key=b"i" * 32,
        password=None,
        fields=["email"],
        raw={"email": "bob@example.test"},
        fingerprint=finding.fingerprint,
        seen_at=NOW,
    )

    upserted = await SQLAlchemyIngestRepository(db).upsert_finding(draft)  # type: ignore[arg-type]
    assert upserted.is_new is True
    assert db.statement is not None
    sql = str(db.statement.compile(dialect=postgresql.dialect()))  # type: ignore[union-attr]
    assert "ON CONFLICT ON CONSTRAINT uq_findings_fingerprint DO UPDATE" in sql
    assert "last_seen_at = excluded.last_seen_at" in sql
    assert "xmax = 0" in sql
