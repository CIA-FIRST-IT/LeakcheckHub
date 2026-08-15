"""Tests for request transaction handling."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest

import app.db as database


@dataclass
class FakeDatabaseSession:
    commit: AsyncMock = field(default_factory=AsyncMock)
    rollback: AsyncMock = field(default_factory=AsyncMock)


class FakeSessionContext:
    def __init__(self, session: FakeDatabaseSession) -> None:
        self._session = session

    async def __aenter__(self) -> FakeDatabaseSession:
        return self._session

    async def __aexit__(self, *_: object) -> None:
        return None


@pytest.mark.anyio
async def test_request_database_session_commits_after_a_successful_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeDatabaseSession()
    monkeypatch.setattr(
        database,
        "get_async_session_factory",
        lambda: lambda: FakeSessionContext(session),
    )

    async for yielded in database.get_db_session():
        assert yielded is session

    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()


@pytest.mark.anyio
async def test_request_database_session_rolls_back_after_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeDatabaseSession()
    monkeypatch.setattr(
        database,
        "get_async_session_factory",
        lambda: lambda: FakeSessionContext(session),
    )

    dependency = database.get_db_session()
    assert await anext(dependency) is session
    error = RuntimeError("handler failed")
    with pytest.raises(RuntimeError, match="handler failed"):
        await dependency.athrow(error)

    session.commit.assert_not_awaited()
    session.rollback.assert_awaited_once()
