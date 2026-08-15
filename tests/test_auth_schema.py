"""Schema-level guardrails for authentication persistence."""

from __future__ import annotations

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models import AdminCredential, Session, User, UserRole, UserSource


def test_user_enums_use_stable_lowercase_values() -> None:
    assert {role.value for role in UserRole} == {"user", "analyst", "super_admin"}
    assert {source.value for source in UserSource} == {"google", "workspace_sync", "manual"}


def test_users_schema_uses_case_insensitive_unique_email() -> None:
    statement = str(CreateTable(User.__table__).compile(dialect=postgresql.dialect()))

    assert "email CITEXT NOT NULL" in statement
    assert "CONSTRAINT uq_users_email UNIQUE (email)" in statement
    assert "CONSTRAINT uq_users_google_sub UNIQUE (google_sub)" in statement


def test_admin_credentials_are_one_to_one_and_sensitive_columns_are_deferred() -> None:
    relationship = User.__mapper__.relationships["admin_credentials"]

    assert relationship.uselist is False
    assert relationship.lazy == "raise"
    assert AdminCredential.__table__.primary_key.columns.keys() == ["user_id"]
    assert AdminCredential.__mapper__.attrs.password_hash.deferred is True
    assert AdminCredential.__mapper__.attrs.password_hash.raiseload is True
    assert AdminCredential.__mapper__.attrs.totp_secret_enc.deferred is True
    assert AdminCredential.__mapper__.attrs.totp_secret_enc.raiseload is True


def test_sessions_store_only_hash_material_and_expiry_constraints() -> None:
    statement = str(CreateTable(Session.__table__).compile(dialect=postgresql.dialect()))

    assert "id_hash BYTEA NOT NULL" in statement
    assert (
        "CONSTRAINT ck_sessions_expires_after_created CHECK (expires_at > created_at)" in statement
    )
    assert (
        "CONSTRAINT ck_sessions_idle_expires_after_created CHECK (idle_expires_at > created_at)"
        in statement
    )
    assert "CONSTRAINT ck_sessions_id_hash_length CHECK (octet_length(id_hash) = 32)" in statement
    assert "CONSTRAINT ck_sessions_ip_hash_length CHECK (octet_length(ip_hash) = 32)" in statement
    assert "CONSTRAINT ck_sessions_ua_hash_length CHECK (octet_length(ua_hash) = 32)" in statement
    assert "token" not in Session.__table__.columns
