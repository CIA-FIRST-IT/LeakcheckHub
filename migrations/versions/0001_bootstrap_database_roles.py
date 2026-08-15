"""Bootstrap least-privilege migration and runtime database roles.

Revision ID: 0001_bootstrap_roles
Revises:
Create Date: 2026-08-15 00:00:00.000000
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

from alembic import op

revision: str = "0001_bootstrap_roles"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _bootstrap_password(name: str) -> str:
    value = os.environ.get(name)
    if value is None or len(value) < 32 or value.startswith("replace-with-"):
        msg = f"{name} must contain a non-placeholder password of at least 32 characters"
        raise RuntimeError(msg)
    # PostgreSQL utility statements cannot use bound parameters for role passwords. Doubling a quote
    # preserves the literal and keeps the secret out of interpolation contexts other than its SQL literal.
    return value.replace("'", "''")


def _quote_identifier(identifier: str) -> str:
    if not _IDENTIFIER.fullmatch(identifier):
        msg = "database name contains unsupported characters"
        raise RuntimeError(msg)
    return f'"{identifier}"'


def upgrade() -> None:
    """Create non-superuser roles and transfer Alembic ownership to the migration role."""

    connection = op.get_bind()
    database_name = connection.exec_driver_sql("SELECT current_database()").scalar_one()
    quoted_database = _quote_identifier(database_name)
    migrator_password = _bootstrap_password("LC_MIGRATOR_DB_PASSWORD")
    runtime_password = _bootstrap_password("LC_RUNTIME_DB_PASSWORD")

    connection.exec_driver_sql(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'leakcheck_migrator') THEN "
        f"CREATE ROLE leakcheck_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        f"NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{migrator_password}'; "
        "END IF; "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'leakcheck_runtime') THEN "
        f"CREATE ROLE leakcheck_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        f"NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{runtime_password}'; "
        "END IF; "
        "END $$"
    )
    connection.exec_driver_sql(f"GRANT CONNECT ON DATABASE {quoted_database} TO leakcheck_migrator")
    # `citext` is a trusted extension. PostgreSQL requires CREATE on the database to install it;
    # migration code otherwise remains confined to the public schema.
    connection.exec_driver_sql(f"GRANT CREATE ON DATABASE {quoted_database} TO leakcheck_migrator")
    connection.exec_driver_sql(f"GRANT CONNECT ON DATABASE {quoted_database} TO leakcheck_runtime")
    connection.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    connection.exec_driver_sql("GRANT USAGE, CREATE ON SCHEMA public TO leakcheck_migrator")
    connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO leakcheck_runtime")
    connection.exec_driver_sql("ALTER TABLE alembic_version OWNER TO leakcheck_migrator")
    connection.exec_driver_sql("GRANT SELECT ON TABLE alembic_version TO leakcheck_runtime")


def downgrade() -> None:
    """Remove bootstrap roles once later migrations have been downgraded."""

    connection = op.get_bind()
    connection.exec_driver_sql("DROP ROLE IF EXISTS leakcheck_runtime")
    connection.exec_driver_sql("DROP ROLE IF EXISTS leakcheck_migrator")
