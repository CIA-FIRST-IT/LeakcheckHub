"""Configurable finding-retention tests.

Deletion is irreversible and is not recorded in the event trail, so the default must be to keep
everything and only remediated findings may ever be removed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.platform_settings import SettingKey
from app.retention import (
    MODE_DAYS,
    MODE_INDEFINITE,
    MODE_NONE,
    RetentionPolicy,
    load_policy,
    purge_expired_findings,
)

_NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


class _Store:
    def __init__(self, values: dict[SettingKey, str | None]) -> None:
        self._values = values

    async def read_many(self, _: object, keys: object) -> dict[SettingKey, str | None]:
        return self._values


class _CountingSession:
    """Records the statements a purge issues without needing a database."""

    def __init__(self, eligible: list[uuid.UUID]) -> None:
        self._eligible = eligible
        self.deletes = 0

    async def execute(self, statement: object) -> object:
        if self.deletes or "SELECT" in str(statement).upper()[:10]:
            if not self.deletes:
                return _Scalars(self._eligible)
        text = str(statement).upper()
        if text.startswith("DELETE"):
            self.deletes += 1
            return None
        return _Scalars(self._eligible)

    async def flush(self) -> None:
        return None


class _Scalars:
    def __init__(self, rows: list[uuid.UUID]) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return self

    def all(self) -> list[uuid.UUID]:
        return self._rows


@pytest.mark.anyio
async def test_an_unconfigured_deployment_keeps_everything() -> None:
    policy = await load_policy(None, _Store({}))  # type: ignore[arg-type]

    assert policy.mode == MODE_INDEFINITE
    assert policy.deletes_anything is False


@pytest.mark.anyio
@pytest.mark.parametrize(
    "values",
    [
        {SettingKey.RETENTION_MODE: "days", SettingKey.RETENTION_DAYS: None},
        {SettingKey.RETENTION_MODE: "days", SettingKey.RETENTION_DAYS: "0"},
        {SettingKey.RETENTION_MODE: "days", SettingKey.RETENTION_DAYS: "not-a-number"},
        {SettingKey.RETENTION_MODE: "wipe-everything", SettingKey.RETENTION_DAYS: "1"},
    ],
)
async def test_an_unusable_policy_deletes_nothing(values: dict[SettingKey, str | None]) -> None:
    """A malformed policy must fail closed towards keeping data, never towards deleting it."""

    policy = await load_policy(None, _Store(values))  # type: ignore[arg-type]

    assert policy.deletes_anything is False


def test_cutoffs_follow_the_configured_mode() -> None:
    assert RetentionPolicy(mode=MODE_NONE).cutoff(now=_NOW) == _NOW
    assert RetentionPolicy(mode=MODE_DAYS, days=30).cutoff(now=_NOW) == _NOW - timedelta(days=30)
    with pytest.raises(ValueError, match="no cutoff"):
        RetentionPolicy().cutoff(now=_NOW)


@pytest.mark.anyio
async def test_indefinite_retention_issues_no_delete() -> None:
    session = _CountingSession([uuid.uuid4()])

    removed = await purge_expired_findings(session, _Store({}), now=_NOW)  # type: ignore[arg-type]

    assert removed == 0
    assert session.deletes == 0


def test_descriptions_state_what_will_be_deleted() -> None:
    assert "indefinitely" in RetentionPolicy().describe()
    assert "as soon as" in RetentionPolicy(mode=MODE_NONE).describe()
    assert "90 days" in RetentionPolicy(mode=MODE_DAYS, days=90).describe()
