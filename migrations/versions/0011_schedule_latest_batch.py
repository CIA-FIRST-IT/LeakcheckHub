"""link schedules to their latest result batch

Revision ID: 0011_schedule_latest_batch
Revises: 0010_optional_mfa_enrollment
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_schedule_latest_batch"
down_revision: str | None = "0010_optional_mfa_enrollment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "schedules",
        sa.Column("last_batch_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_schedules_last_batch_id",
        "schedules",
        "scan_batches",
        ["last_batch_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_schedules_last_batch_id", "schedules", ["last_batch_id"])


def downgrade() -> None:
    op.drop_index("ix_schedules_last_batch_id", table_name="schedules")
    op.drop_constraint("fk_schedules_last_batch_id", "schedules", type_="foreignkey")
    op.drop_column("schedules", "last_batch_id")
