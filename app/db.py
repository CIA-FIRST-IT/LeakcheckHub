"""Async database engine and request-session plumbing.

The engine is deliberately lazy: importing an application module must not open a database connection
or make configuration errors less visible.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings


@lru_cache
def get_async_session_factory() -> async_sessionmaker[AsyncSession]:
    """Create the process-local runtime-role session factory."""

    engine = create_async_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
    )
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Yield one transaction-aware session and commit only a successful request."""

    session_factory = get_async_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
