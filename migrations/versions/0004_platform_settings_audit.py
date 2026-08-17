"""Add encrypted platform settings and append-only audit history.

Revision ID: 0004_platform_settings_audit
Revises: 0003_admin_login_rate_limits
Create Date: 2026-08-17 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_platform_settings_audit"
down_revision: str | Sequence[str] | None = "0003_admin_login_rate_limits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create configuration and audit tables with deliberately narrow runtime grants."""

    op.create_table(
        "platform_settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("schema_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.CheckConstraint("octet_length(nonce) = 12", name="ck_platform_settings_nonce_length"),
        sa.CheckConstraint("schema_version > 0", name="ck_platform_settings_schema_version"),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], name="fk_platform_settings_updated_by"
        ),
        sa.PrimaryKeyConstraint("key", name="pk_platform_settings"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=True),
        sa.Column("target_id", sa.String(length=255), nullable=True),
        sa.Column("ip_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "meta", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.CheckConstraint("octet_length(ip_hash) = 32", name="ck_audit_log_ip_hash_length"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], name="fk_audit_log_actor_id"),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_actor_id", "audit_log", ["actor_id"])

    op.execute("GRANT SELECT, INSERT, UPDATE ON platform_settings TO leakcheck_runtime")
    op.execute("GRANT SELECT, INSERT ON audit_log TO leakcheck_runtime")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM leakcheck_runtime")


def downgrade() -> None:
    """Remove platform settings and audit history."""

    op.execute("REVOKE ALL ON audit_log FROM leakcheck_runtime")
    op.execute("REVOKE ALL ON platform_settings FROM leakcheck_runtime")
    op.drop_index("ix_audit_log_actor_id", table_name="audit_log")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("platform_settings")
