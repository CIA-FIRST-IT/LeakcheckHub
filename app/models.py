"""SQLAlchemy models for the portal's persisted state."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CITEXT, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all portal tables."""


class UserRole(StrEnum):
    """Roles are deliberately small and are enforced at the database boundary."""

    USER = "user"
    ANALYST = "analyst"
    SUPER_ADMIN = "super_admin"


class UserSource(StrEnum):
    """How a user identity entered the portal."""

    GOOGLE = "google"
    WORKSPACE_SYNC = "workspace_sync"
    MANUAL = "manual"


class SubjectKind(StrEnum):
    EMAIL = "email"
    DOMAIN = "domain"
    USERNAME = "username"
    PHONE = "phone"
    ORIGIN = "origin"
    PASSWORD = "password"  # noqa: S105  # nosec B105


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    SELF = "self"
    BATCH = "batch"
    SCHEDULED = "scheduled"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class BatchTarget(StrEnum):
    OU = "ou"
    DOMAIN = "domain"
    SELECTION = "selection"


class BatchStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class QueueStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ScheduleKind(StrEnum):
    SCAN_OU = "scan_ou"
    SCAN_DOMAIN = "scan_domain"


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingEventType(StrEnum):
    DISCOVERED = "discovered"
    REMEDIATED = "remediated"
    UNREMEDIATED = "unremediated"
    RE_LEAKED = "re_leaked"
    PASSWORD_VIEWED = "password_viewed"  # noqa: S105  # nosec B105
    NOTIFIED = "notified"
    ALERTED = "alerted"


def _enum_values(enum_type: type[StrEnum]) -> list[str]:
    """Persist the stable lower-case enum values, never their Python member names."""

    return [member.value for member in enum_type]


class User(Base):
    """A person authorised to use the portal or linked to a Workspace identity."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        UniqueConstraint("google_sub", name="uq_users_google_sub"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    google_sub: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ou_path: Mapped[str | None] = mapped_column(String(1024))
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", values_callable=_enum_values),
        nullable=False,
        default=UserRole.USER,
        server_default=UserRole.USER.value,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    source: Mapped[UserSource] = mapped_column(
        Enum(UserSource, name="user_source", values_callable=_enum_values),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # This relationship must never lazy-load a password hash during ordinary user operations.
    admin_credentials: Mapped[AdminCredential | None] = relationship(
        back_populates="user",
        uselist=False,
        lazy="raise",
    )
    sessions: Mapped[list[Session]] = relationship(back_populates="user", lazy="raise")


class AdminCredential(Base):
    """Separate local-super-admin secrets from the normal user-loading path."""

    __tablename__ = "admin_credentials"
    __table_args__ = (
        CheckConstraint("failed_attempts >= 0", name="ck_admin_credentials_attempts"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_admin_credentials_user_id"),
        primary_key=True,
    )
    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        deferred=True,
        deferred_raiseload=True,
    )
    totp_secret_enc: Mapped[bytes] = mapped_column(
        nullable=False,
        deferred=True,
        deferred_raiseload=True,
    )
    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="admin_credentials", lazy="raise")


class AdminLoginRateLimit(Base):
    """A durable, keyed rate-limit bucket for local super-admin authentication."""

    __tablename__ = "admin_login_rate_limits"
    __table_args__ = (
        CheckConstraint("attempts >= 0", name="ck_admin_login_rate_limits_attempts"),
        CheckConstraint(
            "octet_length(ip_hash) = 32", name="ck_admin_login_rate_limits_ip_hash_length"
        ),
    )

    ip_hash: Mapped[bytes] = mapped_column(primary_key=True)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Session(Base):
    """A server-side session keyed by a SHA-256 token hash, never a cleartext token."""

    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="ck_sessions_expires_after_created"),
        CheckConstraint(
            "idle_expires_at > created_at", name="ck_sessions_idle_expires_after_created"
        ),
        CheckConstraint("octet_length(id_hash) = 32", name="ck_sessions_id_hash_length"),
        CheckConstraint("octet_length(ip_hash) = 32", name="ck_sessions_ip_hash_length"),
        CheckConstraint("octet_length(ua_hash) = 32", name="ck_sessions_ua_hash_length"),
    )

    id_hash: Mapped[bytes] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_sessions_user_id"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip_hash: Mapped[bytes] = mapped_column(nullable=False)
    ua_hash: Mapped[bytes] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="sessions", lazy="raise")


class PlatformSetting(Base):
    """One encrypted, super-admin-managed operational setting.

    Endpoint URLs are encrypted so a database-only disclosure does not reveal the organisation's
    internal topology. The row key and schema version are authenticated as AES-GCM associated data.
    """

    __tablename__ = "platform_settings"
    __table_args__ = (
        CheckConstraint("octet_length(nonce) = 12", name="ck_platform_settings_nonce_length"),
        CheckConstraint("schema_version > 0", name="ck_platform_settings_schema_version"),
    )

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_platform_settings_updated_by")
    )


class AuditLog(Base):
    """Append-only security and human-action history."""

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint("octet_length(ip_hash) = 32", name="ck_audit_log_ip_hash_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_audit_log_actor_id"), index=True
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(255))
    ip_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    meta: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class Subject(Base):
    """A normalized, scannable identifier; cleartext searched passwords are never persisted."""

    __tablename__ = "subjects"
    __table_args__ = (UniqueConstraint("kind", "value_norm", name="uq_subjects_kind_value_norm"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[SubjectKind] = mapped_column(
        Enum(SubjectKind, name="subject_kind", values_callable=_enum_values), nullable=False
    )
    value_norm: Mapped[str] = mapped_column(String(4096), nullable=False)
    value_display: Mapped[str] = mapped_column(String(4096), nullable=False)
    first_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    linked_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_subjects_linked_user_id"), index=True
    )


class Scan(Base):
    """One bounded scan attempt, including the approximate vendor quota observation."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("result_count >= 0", name="ck_scans_result_count"),
        CheckConstraint("new_count >= 0", name="ck_scans_new_count"),
        CheckConstraint("quota IS NULL OR quota >= 0", name="ck_scans_quota"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subjects.id", name="fk_scans_subject_id"), index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_scans_requested_by"), index=True
    )
    trigger: Mapped[ScanTrigger] = mapped_column(
        Enum(ScanTrigger, name="scan_trigger", values_callable=_enum_values), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=_enum_values),
        nullable=False,
        default=ScanStatus.PENDING,
        server_default=ScanStatus.PENDING.value,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    new_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    quota: Mapped[int | None] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    error: Mapped[str | None] = mapped_column(Text)


class BreachSource(Base):
    """Deduplicated source metadata, with a non-null date sentinel for stable uniqueness."""

    __tablename__ = "breach_sources"
    __table_args__ = (
        UniqueConstraint("name_norm", "breach_date_norm", name="uq_breach_sources_identity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(1024), nullable=False)
    name_norm: Mapped[str] = mapped_column(String(1024), nullable=False)
    breach_date: Mapped[date | None] = mapped_column()
    breach_date_norm: Mapped[date] = mapped_column(nullable=False)
    unverified: Mapped[bool | None] = mapped_column(Boolean)
    passwordless: Mapped[bool | None] = mapped_column(Boolean)
    compilation: Mapped[bool | None] = mapped_column(Boolean)
    extra: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class Finding(Base):
    """One distinct exposure; credential plaintext exists only inside AES-GCM ciphertext."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),
        CheckConstraint("octet_length(fingerprint) = 32", name="ck_findings_fingerprint_length"),
        CheckConstraint(
            "identity_key IS NULL OR octet_length(identity_key) = 32",
            name="ck_findings_identity_key_length",
        ),
        CheckConstraint(
            "password_sha256 IS NULL OR octet_length(password_sha256) = 32",
            name="ck_findings_password_sha256_length",
        ),
        CheckConstraint(
            "password_nonce IS NULL OR octet_length(password_nonce) = 12",
            name="ck_findings_password_nonce_length",
        ),
        CheckConstraint(
            "password_len IS NULL OR password_len >= 0", name="ck_findings_password_len"
        ),
        Index("ix_findings_subject_remediation", "subject_id", "remediated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subjects.id", name="fk_findings_subject_id"), index=True
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("breach_sources.id", name="fk_findings_source_id"),
        index=True,
    )
    email: Mapped[str | None] = mapped_column(String(320))
    username: Mapped[str | None] = mapped_column(String(1024))
    phone: Mapped[str | None] = mapped_column(String(64))
    origin: Mapped[str | None] = mapped_column(String(4096))
    identity_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_ciphertext: Mapped[bytes | None] = mapped_column(
        LargeBinary, deferred=True, deferred_raiseload=True
    )
    password_nonce: Mapped[bytes | None] = mapped_column(
        LargeBinary, deferred=True, deferred_raiseload=True
    )
    password_sha256: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_mask: Mapped[str | None] = mapped_column(String(1024))
    password_len: Mapped[int | None] = mapped_column(Integer)
    password_charset: Mapped[str | None] = mapped_column(String(255))
    fields: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    raw: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    fingerprint: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", values_callable=_enum_values),
        nullable=False,
        default=FindingSeverity.MEDIUM,
        server_default=FindingSeverity.MEDIUM.value,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    remediated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_findings_remediated_by")
    )
    remediation_note: Mapped[str | None] = mapped_column(Text)
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", name="fk_findings_superseded_by_id")
    )
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvent(Base):
    """Append-only finding state transition history."""

    __tablename__ = "finding_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", name="fk_finding_events_finding_id"),
        index=True,
    )
    event: Mapped[FindingEventType] = mapped_column(
        Enum(FindingEventType, name="finding_event_type", values_callable=_enum_values),
        nullable=False,
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_finding_events_actor_id")
    )
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    meta: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class ScanBatch(Base):
    """Durable background batch with an immutable target description."""

    __tablename__ = "scan_batches"
    __table_args__ = (
        CheckConstraint("total_count >= 0", name="ck_scan_batches_total_count"),
        CheckConstraint("completed_count >= 0", name="ck_scan_batches_completed_count"),
        CheckConstraint("failed_count >= 0", name="ck_scan_batches_failed_count"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_type: Mapped[BatchTarget] = mapped_column(
        Enum(BatchTarget, name="batch_target", values_callable=_enum_values), nullable=False
    )
    target: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    status: Mapped[BatchStatus] = mapped_column(
        Enum(BatchStatus, name="batch_status", values_callable=_enum_values),
        nullable=False,
        default=BatchStatus.PENDING,
        server_default=BatchStatus.PENDING.value,
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_scan_batches_created_by"), index=True
    )
    total_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    completed_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    failed_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanQueue(Base):
    """A resumable unit of batch work claimed with row-level locking."""

    __tablename__ = "scan_queue"
    __table_args__ = (
        UniqueConstraint("batch_id", "subject_id", name="uq_scan_queue_batch_subject"),
        CheckConstraint("attempts >= 0", name="ck_scan_queue_attempts"),
        Index("ix_scan_queue_claim", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_batches.id", name="fk_scan_queue_batch_id"), index=True
    )
    subject_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subjects.id", name="fk_scan_queue_subject_id"), index=True
    )
    status: Mapped[QueueStatus] = mapped_column(
        Enum(QueueStatus, name="queue_status", values_callable=_enum_values),
        nullable=False,
        default=QueueStatus.QUEUED,
        server_default=QueueStatus.QUEUED.value,
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    locked_by: Mapped[str | None] = mapped_column(String(255))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Schedule(Base):
    """PostgreSQL-backed recurring batch definition evaluated by APScheduler cron triggers."""

    __tablename__ = "schedules"
    __table_args__ = (
        CheckConstraint("misfire_grace_seconds >= 0", name="ck_schedules_misfire_grace"),
        Index("ix_schedules_due", "enabled", "next_run_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[ScheduleKind] = mapped_column(
        Enum(ScheduleKind, name="schedule_kind", values_callable=_enum_values), nullable=False
    )
    target: Mapped[str] = mapped_column(String(1024), nullable=False)
    cron: Mapped[str] = mapped_column(String(255), nullable=False)
    timezone: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    misfire_grace_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=300, server_default="300"
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", name="fk_schedules_created_by"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
