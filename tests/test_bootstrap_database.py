"""Update-safe database bootstrap checks."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.bootstrap_database import _bootstrap_required, _migration_url


@dataclass
class FakeConnection:
    values: list[object | None]
    statements: list[str] = field(default_factory=list)

    async def scalar(self, statement: object) -> object | None:
        self.statements.append(str(statement))
        return self.values.pop(0)


@pytest.mark.anyio
async def test_bootstrap_is_required_only_before_an_alembic_revision_exists() -> None:
    fresh = FakeConnection([None])
    assert await _bootstrap_required(fresh)  # type: ignore[arg-type]
    assert len(fresh.statements) == 1

    migrated = FakeConnection(["alembic_version", "0011_schedule_latest_batch"])
    assert not await _bootstrap_required(migrated)  # type: ignore[arg-type]
    assert len(migrated.statements) == 2


def test_bootstrap_requires_an_async_postgres_migration_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LC_MIGRATION_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="postgresql\\+asyncpg"):
        _migration_url()

    expected = "postgresql+asyncpg://postgres:secret@postgres/leakcheck"
    monkeypatch.setenv("LC_MIGRATION_DATABASE_URL", expected)
    assert _migration_url() == expected
