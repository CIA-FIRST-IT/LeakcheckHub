"""notification outbox and digest schedules

Revision ID: 0008_notifications
Revises: 0007_scheduling
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_notifications"
down_revision: str | None = "0007_scheduling"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE schedule_kind ADD VALUE IF NOT EXISTS 'digest'")
    status = postgresql.ENUM(
        "pending",
        "dry_run",
        "sent",
        "suppressed",
        "failed",
        name="notification_status",
        create_type=False,
    )
    status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("template", sa.String(length=64), nullable=False),
        sa.Column("finding_ids", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("status", status, server_default="pending", nullable=False),
        sa.Column("dedupe_key", sa.LargeBinary(), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error", sa.String(length=255)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("octet_length(dedupe_key) = 32", name="ck_notifications_dedupe_key"),
        sa.CheckConstraint("attempts >= 0", name="ck_notifications_attempts"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_notifications_user_id"),
        sa.PrimaryKeyConstraint("id", name="pk_notifications"),
        sa.UniqueConstraint("dedupe_key", name="uq_notifications_dedupe_key"),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])
    op.create_index("ix_notifications_claim", "notifications", ["status", "created_at"])
    op.create_index("ix_notifications_user_sent", "notifications", ["user_id", "sent_at"])
    op.execute("GRANT SELECT, INSERT, UPDATE ON notifications TO leakcheck_runtime")


def downgrade() -> None:
    op.execute("REVOKE ALL ON notifications FROM leakcheck_runtime")
    op.drop_index("ix_notifications_user_sent", table_name="notifications")
    op.drop_index("ix_notifications_claim", table_name="notifications")
    op.drop_index("ix_notifications_user_id", table_name="notifications")
    op.drop_table("notifications")
    postgresql.ENUM(name="notification_status").drop(op.get_bind(), checkfirst=True)
    # PostgreSQL enum values cannot be removed safely in a transactional downgrade;
    # `digest` remains inert after downgrade.
