"""watchlist and contract-neutral alert outbox

Revision ID: 0009_alert_foundation
Revises: 0008_notifications
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_alert_foundation"
down_revision: str | None = "0008_notifications"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    sink = postgresql.ENUM("wazuh", "dfir_iris", name="alert_sink_name", create_type=False)
    status = postgresql.ENUM(
        "pending", "delivered", "dead_letter", name="alert_outbox_status", create_type=False
    )
    sink.create(op.get_bind(), checkfirst=True)
    status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "watchlist",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True)),
        sa.Column("user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("alert_soc", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("alert_user", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("alert_wazuh", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("alert_iris", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(subject_id IS NOT NULL) <> (user_id IS NOT NULL)",
            name="ck_watchlist_exactly_one_target",
        ),
        sa.ForeignKeyConstraint(["subject_id"], ["subjects.id"], name="fk_watchlist_subject_id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_watchlist_user_id"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_watchlist_created_by"),
        sa.PrimaryKeyConstraint("id", name="pk_watchlist"),
        sa.UniqueConstraint("subject_id", name="uq_watchlist_subject_id"),
        sa.UniqueConstraint("user_id", name="uq_watchlist_user_id"),
    )
    op.create_index("ix_watchlist_created_by", "watchlist", ["created_by"])
    op.create_table(
        "alert_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sink", sink, nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", status, server_default="pending", nullable=False),
        sa.Column("dedupe_key", sa.LargeBinary(), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_error", sa.String(length=255)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("octet_length(dedupe_key) = 32", name="ck_alert_outbox_dedupe_key"),
        sa.CheckConstraint("attempts >= 0", name="ck_alert_outbox_attempts"),
        sa.PrimaryKeyConstraint("id", name="pk_alert_outbox"),
        sa.UniqueConstraint("dedupe_key", name="uq_alert_outbox_dedupe_key"),
    )
    op.create_index("ix_alert_outbox_due", "alert_outbox", ["status", "next_attempt_at"])
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON watchlist TO leakcheck_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON alert_outbox TO leakcheck_runtime")


def downgrade() -> None:
    op.execute("REVOKE ALL ON alert_outbox, watchlist FROM leakcheck_runtime")
    op.drop_index("ix_alert_outbox_due", table_name="alert_outbox")
    op.drop_table("alert_outbox")
    op.drop_index("ix_watchlist_created_by", table_name="watchlist")
    op.drop_table("watchlist")
    postgresql.ENUM(name="alert_outbox_status").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="alert_sink_name").drop(op.get_bind(), checkfirst=True)
