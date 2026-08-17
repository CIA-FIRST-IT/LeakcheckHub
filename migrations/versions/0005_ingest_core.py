"""Add subjects, scans, breach sources, findings, and event history.

Revision ID: 0005_ingest_core
Revises: 0004_platform_settings_audit
Create Date: 2026-08-17 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_ingest_core"
down_revision: str | Sequence[str] | None = "0004_platform_settings_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

subject_kind = postgresql.ENUM(
    "email", "domain", "username", "phone", "origin", "password", name="subject_kind", create_type=False
)
scan_trigger = postgresql.ENUM(
    "manual", "self", "batch", "scheduled", name="scan_trigger", create_type=False
)
scan_status = postgresql.ENUM(
    "pending", "running", "succeeded", "failed", name="scan_status", create_type=False
)
finding_severity = postgresql.ENUM(
    "low", "medium", "high", name="finding_severity", create_type=False
)
finding_event_type = postgresql.ENUM(
    "discovered",
    "remediated",
    "unremediated",
    "re_leaked",
    "password_viewed",
    "notified",
    "alerted",
    name="finding_event_type",
    create_type=False,
)


def upgrade() -> None:
    """Create the ingest schema and preserve append-only event permissions."""

    bind = op.get_bind()
    for enum_type in (
        subject_kind,
        scan_trigger,
        scan_status,
        finding_severity,
        finding_event_type,
    ):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "subjects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", subject_kind, nullable=False),
        sa.Column("value_norm", sa.String(length=4096), nullable=False),
        sa.Column("value_display", sa.String(length=4096), nullable=False),
        sa.Column("first_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("linked_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["linked_user_id"], ["users.id"], name="fk_subjects_linked_user_id"),
        sa.PrimaryKeyConstraint("id", name="pk_subjects"),
        sa.UniqueConstraint("kind", "value_norm", name="uq_subjects_kind_value_norm"),
    )
    op.create_index("ix_subjects_linked_user_id", "subjects", ["linked_user_id"])

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("trigger", scan_trigger, nullable=False),
        sa.Column("status", scan_status, server_default="pending", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("new_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("quota", sa.Integer(), nullable=True),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint("result_count >= 0", name="ck_scans_result_count"),
        sa.CheckConstraint("new_count >= 0", name="ck_scans_new_count"),
        sa.CheckConstraint("quota IS NULL OR quota >= 0", name="ck_scans_quota"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], name="fk_scans_requested_by"),
        sa.ForeignKeyConstraint(["subject_id"], ["subjects.id"], name="fk_scans_subject_id"),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_requested_by", "scans", ["requested_by"])
    op.create_index("ix_scans_subject_id", "scans", ["subject_id"])

    op.create_table(
        "breach_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=1024), nullable=False),
        sa.Column("name_norm", sa.String(length=1024), nullable=False),
        sa.Column("breach_date", sa.Date(), nullable=True),
        sa.Column("breach_date_norm", sa.Date(), nullable=False),
        sa.Column("unverified", sa.Boolean(), nullable=True),
        sa.Column("passwordless", sa.Boolean(), nullable=True),
        sa.Column("compilation", sa.Boolean(), nullable=True),
        sa.Column("extra", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_breach_sources"),
        sa.UniqueConstraint("name_norm", "breach_date_norm", name="uq_breach_sources_identity"),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("username", sa.String(length=1024), nullable=True),
        sa.Column("phone", sa.String(length=64), nullable=True),
        sa.Column("origin", sa.String(length=4096), nullable=True),
        sa.Column("identity_key", sa.LargeBinary(), nullable=True),
        sa.Column("password_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("password_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("password_sha256", sa.LargeBinary(), nullable=True),
        sa.Column("password_mask", sa.String(length=1024), nullable=True),
        sa.Column("password_len", sa.Integer(), nullable=True),
        sa.Column("password_charset", sa.String(length=255), nullable=True),
        sa.Column("fields", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("raw", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("fingerprint", sa.LargeBinary(), nullable=False),
        sa.Column("severity", finding_severity, server_default="medium", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("remediated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("remediation_note", sa.Text(), nullable=True),
        sa.Column("superseded_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("octet_length(fingerprint) = 32", name="ck_findings_fingerprint_length"),
        sa.CheckConstraint(
            "identity_key IS NULL OR octet_length(identity_key) = 32",
            name="ck_findings_identity_key_length",
        ),
        sa.CheckConstraint(
            "password_sha256 IS NULL OR octet_length(password_sha256) = 32",
            name="ck_findings_password_sha256_length",
        ),
        sa.CheckConstraint(
            "password_nonce IS NULL OR octet_length(password_nonce) = 12",
            name="ck_findings_password_nonce_length",
        ),
        sa.CheckConstraint("password_len IS NULL OR password_len >= 0", name="ck_findings_password_len"),
        sa.ForeignKeyConstraint(["remediated_by"], ["users.id"], name="fk_findings_remediated_by"),
        sa.ForeignKeyConstraint(["source_id"], ["breach_sources.id"], name="fk_findings_source_id"),
        sa.ForeignKeyConstraint(["subject_id"], ["subjects.id"], name="fk_findings_subject_id"),
        sa.ForeignKeyConstraint(
            ["superseded_by_id"], ["findings.id"], name="fk_findings_superseded_by_id"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),
    )
    op.create_index("ix_findings_source_id", "findings", ["source_id"])
    op.create_index("ix_findings_subject_id", "findings", ["subject_id"])
    op.create_index(
        "ix_findings_subject_remediation", "findings", ["subject_id", "remediated_at"]
    )

    op.create_table(
        "finding_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event", finding_event_type, nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("meta", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], name="fk_finding_events_actor_id"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], name="fk_finding_events_finding_id"),
        sa.PrimaryKeyConstraint("id", name="pk_finding_events"),
    )
    op.create_index("ix_finding_events_finding_id", "finding_events", ["finding_id"])

    for table in ("subjects", "scans", "breach_sources", "findings"):
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {table} TO leakcheck_runtime")
    op.execute("GRANT SELECT, INSERT ON finding_events TO leakcheck_runtime")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON finding_events FROM leakcheck_runtime")


def downgrade() -> None:
    """Drop the ingest schema and its enum types."""

    for table in ("finding_events", "findings", "breach_sources", "scans", "subjects"):
        op.execute(f"REVOKE ALL ON {table} FROM leakcheck_runtime")
    op.drop_index("ix_finding_events_finding_id", table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index("ix_findings_subject_remediation", table_name="findings")
    op.drop_index("ix_findings_subject_id", table_name="findings")
    op.drop_index("ix_findings_source_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("breach_sources")
    op.drop_index("ix_scans_subject_id", table_name="scans")
    op.drop_index("ix_scans_requested_by", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_subjects_linked_user_id", table_name="subjects")
    op.drop_table("subjects")
    for enum_type in (
        finding_event_type,
        finding_severity,
        scan_status,
        scan_trigger,
        subject_kind,
    ):
        enum_type.drop(op.get_bind(), checkfirst=True)
