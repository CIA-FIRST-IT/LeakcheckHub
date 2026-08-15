"""SQLAlchemy models for the portal's persisted state."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CITEXT, UUID
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
