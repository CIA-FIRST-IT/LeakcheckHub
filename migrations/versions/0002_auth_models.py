"""Create authentication and session tables.

Revision ID: 0002_auth_models
Revises: 0001_bootstrap_roles
Create Date: 2026-08-15 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_auth_models"
down_revision: str | Sequence[str] | None = "0001_bootstrap_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

user_role = postgresql.ENUM(
    "user",
    "analyst",
    "super_admin",
    name="user_role",
    create_type=False,
)
user_source = postgresql.ENUM(
    "google",
    "workspace_sync",
    "manual",
    name="user_source",
    create_type=False,
)


def upgrade() -> None:
    """Create auth tables and give only the runtime operations they require."""

    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    user_role.create(op.get_bind(), checkfirst=True)
    user_source.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        sa.Column("google_sub", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("ou_path", sa.String(length=1024), nullable=True),
        sa.Column("role", user_role, server_default=sa.text("'user'::user_role"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("source", user_source, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("google_sub", name="uq_users_google_sub"),
    )
    op.create_table(
        "admin_credentials",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("failed_attempts >= 0", name="ck_admin_credentials_attempts"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_admin_credentials_user_id"),
        sa.PrimaryKeyConstraint("user_id", name="pk_admin_credentials"),
    )
    op.create_table(
        "sessions",
        sa.Column("id_hash", sa.LargeBinary(), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_hash", sa.LargeBinary(), nullable=False),
        sa.Column("ua_hash", sa.LargeBinary(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("expires_at > created_at", name="ck_sessions_expires_after_created"),
        sa.CheckConstraint(
            "idle_expires_at > created_at",
            name="ck_sessions_idle_expires_after_created",
        ),
        sa.CheckConstraint("octet_length(id_hash) = 32", name="ck_sessions_id_hash_length"),
        sa.CheckConstraint("octet_length(ip_hash) = 32", name="ck_sessions_ip_hash_length"),
        sa.CheckConstraint("octet_length(ua_hash) = 32", name="ck_sessions_ua_hash_length"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_sessions_user_id"),
        sa.PrimaryKeyConstraint("id_hash", name="pk_sessions"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"], unique=False)

    op.execute("GRANT SELECT, INSERT, UPDATE ON users TO leakcheck_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON admin_credentials TO leakcheck_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON sessions TO leakcheck_runtime")


def downgrade() -> None:
    """Remove auth tables and their enum types; keep citext available for future migrations."""

    op.execute("REVOKE ALL ON sessions FROM leakcheck_runtime")
    op.execute("REVOKE ALL ON admin_credentials FROM leakcheck_runtime")
    op.execute("REVOKE ALL ON users FROM leakcheck_runtime")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("admin_credentials")
    op.drop_table("users")
    user_source.drop(op.get_bind(), checkfirst=True)
    user_role.drop(op.get_bind(), checkfirst=True)
