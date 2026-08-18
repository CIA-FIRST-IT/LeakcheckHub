"""Run the privileged database-role bootstrap only on a fresh database."""

from __future__ import annotations

import asyncio
import os

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine


def _migration_url() -> str:
    url = os.environ.get("LC_MIGRATION_DATABASE_URL", "")
    if not url.startswith("postgresql+asyncpg://"):
        msg = "LC_MIGRATION_DATABASE_URL must use postgresql+asyncpg://"
        raise RuntimeError(msg)
    return url


async def _bootstrap_required(connection: AsyncConnection) -> bool:
    version_table = await connection.scalar(text("SELECT to_regclass('public.alembic_version')"))
    if version_table is None:
        return True
    revision = await connection.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
    return revision is None


async def _database_needs_bootstrap(url: str) -> bool:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            return await _bootstrap_required(connection)
    finally:
        await engine.dispose()


def main() -> None:
    """Bootstrap roles once; later stack redeployments exit without attempting a downgrade."""

    url = _migration_url()
    if not asyncio.run(_database_needs_bootstrap(url)):
        return
    command.upgrade(Config("alembic.ini"), "0001_bootstrap_roles")


if __name__ == "__main__":
    main()
