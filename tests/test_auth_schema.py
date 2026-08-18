"""Schema-level guardrails for authentication persistence."""

from __future__ import annotations

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models import (
    AdminCredential,
    AdminLoginRateLimit,
    AuditLog,
    BreachSource,
    Finding,
    FindingEvent,
    PlatformSetting,
    Scan,
    Session,
    Subject,
    User,
    UserRole,
    UserSource,
)


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
    assert AdminCredential.__table__.c.totp_secret_enc.nullable is True
    assert AdminCredential.__table__.c.totp_enabled_at.nullable is True


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


def test_local_login_ip_throttle_stores_only_a_keyed_digest() -> None:
    statement = str(
        CreateTable(AdminLoginRateLimit.__table__).compile(dialect=postgresql.dialect())
    )

    assert "ip_hash BYTEA NOT NULL" in statement
    assert (
        "CONSTRAINT ck_admin_login_rate_limits_ip_hash_length CHECK (octet_length(ip_hash) = 32)"
        in statement
    )
    assert "ip_address" not in AdminLoginRateLimit.__table__.columns


def test_platform_settings_are_ciphertext_only_and_audit_is_append_only_by_grant() -> None:
    setting_sql = str(CreateTable(PlatformSetting.__table__).compile(dialect=postgresql.dialect()))
    audit_sql = str(CreateTable(AuditLog.__table__).compile(dialect=postgresql.dialect()))

    assert "ciphertext BYTEA NOT NULL" in setting_sql
    assert "nonce BYTEA NOT NULL" in setting_sql
    assert "value" not in PlatformSetting.__table__.columns
    assert "CONSTRAINT ck_platform_settings_nonce_length" in setting_sql
    assert "ip_hash BYTEA NOT NULL" in audit_sql
    assert "CONSTRAINT ck_audit_log_ip_hash_length" in audit_sql


def test_ingest_schema_has_stable_uniqueness_crypto_and_quota_constraints() -> None:
    subject_sql = str(CreateTable(Subject.__table__).compile(dialect=postgresql.dialect()))
    scan_sql = str(CreateTable(Scan.__table__).compile(dialect=postgresql.dialect()))
    source_sql = str(CreateTable(BreachSource.__table__).compile(dialect=postgresql.dialect()))
    finding_sql = str(CreateTable(Finding.__table__).compile(dialect=postgresql.dialect()))
    event_sql = str(CreateTable(FindingEvent.__table__).compile(dialect=postgresql.dialect()))

    assert "CONSTRAINT uq_subjects_kind_value_norm UNIQUE (kind, value_norm)" in subject_sql
    assert "CONSTRAINT ck_scans_quota CHECK (quota IS NULL OR quota >= 0)" in scan_sql
    assert (
        "CONSTRAINT uq_breach_sources_identity UNIQUE (name_norm, breach_date_norm)" in source_sql
    )
    assert "CONSTRAINT uq_findings_fingerprint UNIQUE (fingerprint)" in finding_sql
    assert "CONSTRAINT ck_findings_password_nonce_length" in finding_sql
    assert "finding_id UUID NOT NULL" in event_sql
    assert Finding.__mapper__.attrs.password_ciphertext.deferred is True
    assert Finding.__mapper__.attrs.password_ciphertext.raiseload is True
