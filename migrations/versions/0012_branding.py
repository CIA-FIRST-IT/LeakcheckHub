"""organisation name and logo for the landing page

Revision ID: 0012_branding
Revises: 0011_schedule_latest_batch
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_branding"
down_revision: str | None = "0011_schedule_latest_batch"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "branding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_name", sa.String(length=120), nullable=True),
        sa.Column("logo", sa.LargeBinary(), nullable=True),
        sa.Column("logo_content_type", sa.String(length=64), nullable=True),
        sa.Column("logo_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_branding"),
        sa.CheckConstraint("id = 1", name="ck_branding_single_row"),
        sa.CheckConstraint(
            "logo IS NULL OR octet_length(logo) <= 1048576", name="ck_branding_logo_size"
        ),
    )


def downgrade() -> None:
    op.drop_table("branding")
