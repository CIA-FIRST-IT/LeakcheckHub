"""workspace sync and durable scan batches

Revision ID: 0006_workspace_batches
Revises: 0005_ingest_core
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_workspace_batches"
down_revision: str | None = "0005_ingest_core"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    batch_target = postgresql.ENUM(
        "ou", "domain", "selection", name="batch_target", create_type=False
    )
    batch_status = postgresql.ENUM(
        "pending", "running", "succeeded", "partial", "failed",
        name="batch_status", create_type=False,
    )
    queue_status = postgresql.ENUM(
        "queued", "running", "succeeded", "failed", name="queue_status", create_type=False
    )
    batch_target.create(op.get_bind(), checkfirst=True)
    batch_status.create(op.get_bind(), checkfirst=True)
    queue_status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "scan_batches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", batch_target, nullable=False),
        sa.Column("target", postgresql.JSONB(), nullable=False),
        sa.Column("status", batch_status, server_default="pending", nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("total_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("completed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("total_count >= 0", name="ck_scan_batches_total_count"),
        sa.CheckConstraint("completed_count >= 0", name="ck_scan_batches_completed_count"),
        sa.CheckConstraint("failed_count >= 0", name="ck_scan_batches_failed_count"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_scan_batches_created_by"),
        sa.PrimaryKeyConstraint("id", name="pk_scan_batches"),
    )
    op.create_index("ix_scan_batches_created_by", "scan_batches", ["created_by"])
    op.create_table(
        "scan_queue",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", queue_status, server_default="queued", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_by", sa.String(length=255)),
        sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=255)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("attempts >= 0", name="ck_scan_queue_attempts"),
        sa.ForeignKeyConstraint(["batch_id"], ["scan_batches.id"], name="fk_scan_queue_batch_id"),
        sa.ForeignKeyConstraint(["subject_id"], ["subjects.id"], name="fk_scan_queue_subject_id"),
        sa.PrimaryKeyConstraint("id", name="pk_scan_queue"),
        sa.UniqueConstraint("batch_id", "subject_id", name="uq_scan_queue_batch_subject"),
    )
    op.create_index("ix_scan_queue_batch_id", "scan_queue", ["batch_id"])
    op.create_index("ix_scan_queue_subject_id", "scan_queue", ["subject_id"])
    op.create_index("ix_scan_queue_claim", "scan_queue", ["status", "created_at"])
    op.execute("GRANT SELECT, INSERT, UPDATE ON scan_batches, scan_queue TO leakcheck_runtime")


def downgrade() -> None:
    op.execute("REVOKE ALL ON scan_queue, scan_batches FROM leakcheck_runtime")
    op.drop_index("ix_scan_queue_claim", table_name="scan_queue")
    op.drop_index("ix_scan_queue_subject_id", table_name="scan_queue")
    op.drop_index("ix_scan_queue_batch_id", table_name="scan_queue")
    op.drop_table("scan_queue")
    op.drop_index("ix_scan_batches_created_by", table_name="scan_batches")
    op.drop_table("scan_batches")
    for name in ("queue_status", "batch_status", "batch_target"):
        postgresql.ENUM(name=name).drop(op.get_bind(), checkfirst=True)
