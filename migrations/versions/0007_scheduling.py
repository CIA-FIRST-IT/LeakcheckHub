"""persistent recurring schedules

Revision ID: 0007_scheduling
Revises: 0006_workspace_batches
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_scheduling"
down_revision: str | None = "0006_workspace_batches"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    kind = postgresql.ENUM("scan_ou", "scan_domain", name="schedule_kind", create_type=False)
    kind.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", kind, nullable=False),
        sa.Column("target", sa.String(length=1024), nullable=False),
        sa.Column("cron", sa.String(length=255), nullable=False),
        sa.Column("timezone", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("misfire_grace_seconds", sa.Integer(), server_default="300", nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(length=255)),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("misfire_grace_seconds >= 0", name="ck_schedules_misfire_grace"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_schedules_created_by"),
        sa.PrimaryKeyConstraint("id", name="pk_schedules"),
    )
    op.create_index("ix_schedules_created_by", "schedules", ["created_by"])
    op.create_index("ix_schedules_due", "schedules", ["enabled", "next_run_at"])
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON schedules TO leakcheck_runtime")


def downgrade() -> None:
    op.execute("REVOKE ALL ON schedules FROM leakcheck_runtime")
    op.drop_index("ix_schedules_due", table_name="schedules")
    op.drop_index("ix_schedules_created_by", table_name="schedules")
    op.drop_table("schedules")
    postgresql.ENUM(name="schedule_kind").drop(op.get_bind(), checkfirst=True)
