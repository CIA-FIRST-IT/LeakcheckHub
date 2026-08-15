"""Add a persistent per-IP throttle for local super-admin login.

Revision ID: 0003_admin_login_rate_limits
Revises: 0002_auth_models
Create Date: 2026-08-15 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0003_admin_login_rate_limits"
down_revision: str | Sequence[str] | None = "0002_auth_models"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Persist keyed IP throttle buckets so the limit survives and spans web replicas."""

    op.create_table(
        "admin_login_rate_limits",
        sa.Column("ip_hash", sa.LargeBinary(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("attempts >= 0", name="ck_admin_login_rate_limits_attempts"),
        sa.CheckConstraint(
            "octet_length(ip_hash) = 32", name="ck_admin_login_rate_limits_ip_hash_length"
        ),
        sa.PrimaryKeyConstraint("ip_hash", name="pk_admin_login_rate_limits"),
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON admin_login_rate_limits TO leakcheck_runtime")


def downgrade() -> None:
    """Remove the throttle table and its runtime-role permissions."""

    op.execute("REVOKE ALL ON admin_login_rate_limits FROM leakcheck_runtime")
    op.drop_table("admin_login_rate_limits")
