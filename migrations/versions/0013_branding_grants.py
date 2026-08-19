"""grant runtime privileges for branding and retention

Revision ID: 0013_branding_grants
Revises: 0012_branding
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0013_branding_grants"
down_revision: str | None = "0012_branding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 0012 created the table without granting the runtime role access to it, so every page that
    # reads branding — including the unauthenticated landing page — failed with a 500.
    op.execute("GRANT SELECT, INSERT, UPDATE ON branding TO leakcheck_runtime")

    # Configurable retention deletes remediated findings, which the runtime role could not do:
    # 0005 granted only SELECT, INSERT, UPDATE on findings and explicitly revoked DELETE on
    # finding_events to keep the trail append-only. Retention cannot work without both, and the
    # foreign key means the events must go first. This deliberately relaxes that guarantee; it
    # only has an effect once an administrator selects a policy other than "keep indefinitely".
    op.execute("GRANT DELETE ON findings TO leakcheck_runtime")
    op.execute("GRANT DELETE ON finding_events TO leakcheck_runtime")


def downgrade() -> None:
    op.execute("REVOKE DELETE ON finding_events FROM leakcheck_runtime")
    op.execute("REVOKE DELETE ON findings FROM leakcheck_runtime")
    op.execute("REVOKE SELECT, INSERT, UPDATE ON branding FROM leakcheck_runtime")
