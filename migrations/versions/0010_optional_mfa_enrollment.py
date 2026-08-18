"""make local MFA an explicit post-login enrollment

Revision ID: 0010_optional_mfa_enrollment
Revises: 0009_alert_foundation
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_optional_mfa_enrollment"
down_revision: str | None = "0009_alert_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "admin_credentials",
        sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Accounts provisioned by earlier releases already received and used this seed.
    op.execute(
        "UPDATE admin_credentials SET totp_enabled_at = now() WHERE totp_secret_enc IS NOT NULL"
    )
    op.alter_column(
        "admin_credentials", "totp_secret_enc", existing_type=sa.LargeBinary(), nullable=True
    )


def downgrade() -> None:
    missing = op.get_bind().execute(
        sa.text("SELECT count(*) FROM admin_credentials WHERE totp_secret_enc IS NULL")
    ).scalar_one()
    if missing:
        raise RuntimeError("enroll or remove password-only local admins before downgrading")
    op.alter_column(
        "admin_credentials", "totp_secret_enc", existing_type=sa.LargeBinary(), nullable=False
    )
    op.drop_column("admin_credentials", "totp_enabled_at")
