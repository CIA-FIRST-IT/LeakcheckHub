"""Encryption and blank-slate tests for database-backed platform configuration."""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest

from app.config import Settings
from app.models import PlatformSetting
from app.platform_settings import (
    SECRET_KEYS,
    PlatformSettingError,
    PlatformSettingsStore,
    SettingKey,
)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )


@dataclass
class FakeResult:
    row: PlatformSetting | None

    def scalar_one_or_none(self) -> PlatformSetting | None:
        return self.row


@dataclass
class FakeDB:
    row: PlatformSetting | None = None
    added: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    async def execute(self, statement: object) -> FakeResult:
        del statement
        return FakeResult(self.row)

    def add(self, value: object) -> None:
        self.added.append(value)


@pytest.mark.anyio
async def test_secret_is_encrypted_bound_to_its_key_and_never_repr_exposed() -> None:
    store = PlatformSettingsStore(make_settings())
    write_db = FakeDB()
    actor_id = uuid.uuid4()
    secret = "live-enterprise-api-key"  # noqa: S105 - synthetic encryption fixture

    await store.write_many(
        write_db,  # type: ignore[arg-type]
        {SettingKey.LEAKCHECK_API_KEY: secret},
        actor_id=actor_id,
    )

    assert len(write_db.added) == 1
    row = write_db.added[0]
    assert isinstance(row, PlatformSetting)
    assert secret.encode() not in row.ciphertext
    assert secret not in repr(row)
    assert row.updated_by == actor_id
    assert await store.read(FakeDB(row=row), SettingKey.LEAKCHECK_API_KEY) == secret  # type: ignore[arg-type]

    row.key = SettingKey.GOOGLE_CLIENT_SECRET.value
    with pytest.raises(PlatformSettingError):
        await store.read(FakeDB(row=row), SettingKey.GOOGLE_CLIENT_SECRET)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_blank_secret_preserves_existing_configuration() -> None:
    store = PlatformSettingsStore(make_settings())
    db = FakeDB()

    await store.write_many(
        db,  # type: ignore[arg-type]
        {SettingKey.LEAKCHECK_API_KEY: ""},
        actor_id=uuid.uuid4(),
    )

    assert db.added == []
    db.flush.assert_awaited_once()


def test_shipping_configuration_has_no_operational_integration_values() -> None:
    assert not any(name.startswith("google_") for name in Settings.model_fields)
    assert not any(name.startswith("leakcheck_") for name in Settings.model_fields)


def test_workspace_service_account_document_is_always_treated_as_a_secret() -> None:
    assert SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON in SECRET_KEYS
