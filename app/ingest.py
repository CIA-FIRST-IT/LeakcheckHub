"""Normalize, fingerprint, encrypt, and idempotently ingest LeakCheck records."""

from __future__ import annotations

import hashlib
import unicodedata
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Protocol, cast

from sqlalchemy import literal_column, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.finding_crypto import ProtectedPassword, protect_password
from app.leakcheck import BreachSource as VendorSource
from app.leakcheck import LeakRecord
from app.models import (
    BreachSource,
    Finding,
    FindingEvent,
    FindingEventType,
    FindingSeverity,
    Subject,
)
from app.normalization import (
    normalize_optional_email,
    normalize_optional_phone,
    normalize_optional_username,
)

UNKNOWN_DATE = date(1, 1, 1)
UNKNOWN_SOURCE = "Unknown"
_ZERO_PASSWORD_HASH = b"\x00" * 32


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    name: str
    name_norm: str
    breach_date: date | None
    breach_date_norm: date
    unverified: bool | None
    passwordless: bool | None
    compilation: bool | None
    extra: dict[str, object]


@dataclass(frozen=True, slots=True)
class FindingDraft:
    id: uuid.UUID
    subject_id: uuid.UUID
    source_id: uuid.UUID
    email: str | None
    username: str | None
    phone: str | None
    origin: str | None
    identity_key: bytes | None
    password: ProtectedPassword | None
    fields: list[str]
    raw: dict[str, object]
    fingerprint: bytes
    seen_at: datetime


@dataclass(frozen=True, slots=True)
class UpsertedFinding:
    finding: Finding
    is_new: bool


@dataclass(frozen=True, slots=True)
class IngestSummary:
    findings: tuple[Finding, ...]
    new_count: int
    re_leaked_count: int
    new_finding_ids: tuple[uuid.UUID, ...] = ()


class IngestRepository(Protocol):
    async def resolve_source(self, source: SourceIdentity) -> BreachSource: ...

    async def upsert_finding(self, draft: FindingDraft) -> UpsertedFinding: ...

    async def find_remediated_predecessor(
        self, finding: Finding, source: SourceIdentity
    ) -> Finding | None: ...

    async def link_releak(self, previous: Finding, current: Finding, *, at: datetime) -> None: ...

    async def add_event(
        self,
        finding_id: uuid.UUID,
        event: FindingEventType,
        *,
        actor_id: uuid.UUID | None,
        at: datetime,
        meta: dict[str, object] | None = None,
    ) -> None: ...


class SQLAlchemyIngestRepository:
    """PostgreSQL implementation using conflict-safe source and finding upserts."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def resolve_source(self, source: SourceIdentity) -> BreachSource:
        insert_statement = postgresql_insert(BreachSource).values(
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
        statement = insert_statement.on_conflict_do_update(
            constraint="uq_breach_sources_identity",
            set_={
                "unverified": insert_statement.excluded.unverified,
                "passwordless": insert_statement.excluded.passwordless,
                "compilation": insert_statement.excluded.compilation,
                "extra": insert_statement.excluded.extra,
            },
        ).returning(BreachSource)
        result = await self._db.execute(statement)
        return result.scalar_one()

    async def upsert_finding(self, draft: FindingDraft) -> UpsertedFinding:
        protected = draft.password
        insert_statement = postgresql_insert(Finding).values(
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
        statement: Any = insert_statement.on_conflict_do_update(
            constraint="uq_findings_fingerprint",
            set_={
                "last_seen_at": insert_statement.excluded.last_seen_at,
                "raw": insert_statement.excluded.raw,
                "fields": insert_statement.excluded.fields,
                "origin": insert_statement.excluded.origin,
            },
        ).returning(Finding, literal_column("(xmax = 0)").label("is_new"))
        result = await self._db.execute(statement)
        finding_value, is_new = result.one()
        finding = cast(Finding, finding_value)
        return UpsertedFinding(finding=finding, is_new=bool(is_new))

    async def find_remediated_predecessor(
        self, finding: Finding, source: SourceIdentity
    ) -> Finding | None:
        if source.name_norm == UNKNOWN_SOURCE.casefold() or finding.identity_key is None:
            return None
        result = await self._db.execute(
            select(Finding)
            .join(BreachSource, BreachSource.id == Finding.source_id)
            .where(
                Finding.subject_id == finding.subject_id,
                Finding.id != finding.id,
                Finding.identity_key == finding.identity_key,
                Finding.remediated_at.is_not(None),
                Finding.superseded_by_id.is_(None),
                Finding.password_sha256.is_distinct_from(finding.password_sha256),
                BreachSource.name_norm == source.name_norm,
            )
            .order_by(Finding.remediated_at.desc())
            .limit(1)
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def link_releak(self, previous: Finding, current: Finding, *, at: datetime) -> None:
        previous.superseded_by_id = current.id
        current.severity = FindingSeverity.HIGH
        await self._db.flush()

    async def add_event(
        self,
        finding_id: uuid.UUID,
        event: FindingEventType,
        *,
        actor_id: uuid.UUID | None,
        at: datetime,
        meta: dict[str, object] | None = None,
    ) -> None:
        self._db.add(
            FindingEvent(
                id=uuid.uuid4(),
                finding_id=finding_id,
                event=event,
                actor_id=actor_id,
                at=at,
                meta=meta or {},
            )
        )
        await self._db.flush()


async def ingest_records(
    repository: IngestRepository,
    settings: Settings,
    *,
    subject: Subject,
    records: Sequence[LeakRecord],
    actor_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> IngestSummary:
    """Ingest records idempotently and turn remediated password changes into re-leaks."""

    seen_at = _utc_now(now)
    findings: list[Finding] = []
    new_count = 0
    re_leaked_count = 0
    new_finding_ids: list[uuid.UUID] = []
    for record in records:
        source_identity = normalize_source(record.source)
        source = await repository.resolve_source(source_identity)
        draft = build_finding_draft(
            settings,
            subject=subject,
            source=source,
            source_identity=source_identity,
            record=record,
            seen_at=seen_at,
        )
        upserted = await repository.upsert_finding(draft)
        finding = upserted.finding
        findings.append(finding)
        if not upserted.is_new:
            continue
        new_count += 1
        new_finding_ids.append(finding.id)
        await repository.add_event(
            finding.id,
            FindingEventType.DISCOVERED,
            actor_id=actor_id,
            at=seen_at,
        )
        predecessor = await repository.find_remediated_predecessor(finding, source_identity)
        if predecessor is None:
            continue
        await repository.link_releak(predecessor, finding, at=seen_at)
        await repository.add_event(
            finding.id,
            FindingEventType.RE_LEAKED,
            actor_id=actor_id,
            at=seen_at,
            meta={"previous_finding_id": str(predecessor.id)},
        )
        re_leaked_count += 1
    return IngestSummary(tuple(findings), new_count, re_leaked_count, tuple(new_finding_ids))


def build_finding_draft(
    settings: Settings,
    *,
    subject: Subject,
    source: BreachSource,
    source_identity: SourceIdentity,
    record: LeakRecord,
    seen_at: datetime,
) -> FindingDraft:
    finding_id = uuid.uuid4()
    protected = (
        protect_password(settings, finding_id=finding_id, password=record.password)
        if record.password is not None
        else None
    )
    email_norm = normalize_optional_email(record.email)
    username_norm = normalize_optional_username(record.username)
    phone_norm = normalize_optional_phone(record.phone)
    identity_key = _identity_key(email_norm, username_norm, phone_norm)
    fingerprint = finding_fingerprint(
        subject=subject,
        source=source_identity,
        email_norm=email_norm,
        username_norm=username_norm,
        phone_norm=phone_norm,
        password_sha256=protected.sha256 if protected else None,
    )
    raw = _sanitized_raw(record.raw)
    return FindingDraft(
        id=finding_id,
        subject_id=subject.id,
        source_id=source.id,
        email=record.email,
        username=record.username,
        phone=record.phone,
        origin=record.origin,
        identity_key=identity_key,
        password=protected,
        fields=list(record.fields),
        raw=raw,
        fingerprint=fingerprint,
        seen_at=seen_at,
    )


def finding_fingerprint(
    *,
    subject: Subject,
    source: SourceIdentity,
    email_norm: str,
    username_norm: str,
    phone_norm: str,
    password_sha256: bytes | None,
) -> bytes:
    parts = (
        subject.kind.value.encode(),
        subject.value_norm.encode(),
        source.name_norm.encode(),
        source.breach_date_norm.isoformat().encode(),
        email_norm.encode(),
        username_norm.encode(),
        phone_norm.encode(),
        password_sha256 or _ZERO_PASSWORD_HASH,
    )
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def normalize_source(source: VendorSource) -> SourceIdentity:
    name = unicodedata.normalize("NFKC", source.name or UNKNOWN_SOURCE).strip() or UNKNOWN_SOURCE
    name = "".join(character if character.isprintable() else "�" for character in name)
    name = name[:1024]
    breach_date = _parse_date(source.breach_date)
    extra: dict[str, object] = {
        "vendor_name": source.name,
        "vendor_breach_date": source.breach_date,
    }
    return SourceIdentity(
        name=name,
        name_norm=name.casefold(),
        breach_date=breach_date,
        breach_date_norm=breach_date or UNKNOWN_DATE,
        unverified=source.unverified,
        passwordless=source.passwordless,
        compilation=source.compilation,
        extra=extra,
    )


def _identity_key(email: str, username: str, phone: str) -> bytes | None:
    if not any((email, username, phone)):
        return None
    digest = hashlib.sha256()
    for value in (email, username, phone):
        encoded = value.encode()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _sanitized_raw(value: dict[str, object]) -> dict[str, object]:
    """Recursively remove password values before JSON serialization."""

    sanitized: dict[str, object] = {}
    for key, item in value.items():
        if key.casefold() == "password":
            continue
        sanitized[key] = _sanitize_value(item)
    return sanitized


def _sanitize_value(value: object) -> object:
    if isinstance(value, dict):
        return _sanitized_raw(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    return value


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("ingest timestamps must be timezone-aware")
    return current.astimezone(UTC)
