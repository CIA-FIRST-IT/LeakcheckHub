"""Alembic async migration environment.

Migrations intentionally use a separate connection string, never the web process's runtime role.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _migration_url() -> str:
    url = os.environ.get("LC_MIGRATION_DATABASE_URL")
    if not url:
        msg = "LC_MIGRATION_DATABASE_URL is required to run migrations"
        raise RuntimeError(msg)
    if not url.startswith("postgresql+asyncpg://"):
        msg = "LC_MIGRATION_DATABASE_URL must use postgresql+asyncpg://"
        raise RuntimeError(msg)
    return url


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _migration_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    msg = "Offline migrations are disabled because this project uses async PostgreSQL connections"
    raise RuntimeError(msg)
run_migrations_online()

