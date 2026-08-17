"""Audit events store only keyed address fingerprints and non-secret metadata."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from app.audit import audit_event
from app.config import Settings
from app.models import AuditLog


@dataclass
class FakeDB:
    added: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    def add(self, value: object) -> None:
        self.added.append(value)


@pytest.mark.anyio
async def test_audit_event_hashes_client_address_and_appends_once() -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/auth/logout",
            "headers": [],
            "client": ("192.0.2.10", 1234),
        }
    )
    db = FakeDB()

    event = await audit_event(
        db,  # type: ignore[arg-type]
        request,
        settings,
        action="auth.logout",
    )

    assert isinstance(event, AuditLog)
    assert len(event.ip_hash) == 32
    assert event.ip_hash != b"192.0.2.10"
    assert db.added == [event]
    db.flush.assert_awaited_once()
