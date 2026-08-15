"""Tests for server-side opaque session lifecycle rules."""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import Response

from app.auth.session import SESSION_COOKIE_NAME, IssuedSession, SessionManager
from app.config import Settings
from app.models import Session, User, UserSource

SESSION_SECRET = "s" * 32
NOW = datetime(2026, 8, 15, 12, tzinfo=UTC)


@dataclass
class FakeResult:
    row: tuple[Session, User] | None = None
    scalar: Session | None = None
    rowcount: int | None = None

    def one_or_none(self) -> tuple[Session, User] | None:
        return self.row

    def scalar_one_or_none(self) -> Session | None:
        return self.scalar


@dataclass
class FakeAsyncSession:
    result: FakeResult = field(default_factory=FakeResult)
    added: list[object] = field(default_factory=list)
    execute_calls: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def execute(self, statement: object) -> FakeResult:
        self.execute_calls.append(statement)
        return self.result


def make_manager(
    *, idle_seconds: int = 60 * 60, absolute_seconds: int = 12 * 60 * 60
) -> SessionManager:
    return SessionManager(
        Settings(
            database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
            session_secret=SESSION_SECRET,
            google_client_id="portal-client-id.apps.googleusercontent.com",
            google_client_secret="c" * 32,
            google_redirect_uri="https://portal.example.test/auth/google/callback",
            google_workspace_domains=("example.test",),
            data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
            trusted_hosts=("testserver",),
            session_idle_ttl_seconds=idle_seconds,
            session_absolute_ttl_seconds=absolute_seconds,
        )
    )


def make_user(*, active: bool = True) -> User:
    return User(
        id=uuid.uuid4(),
        email="analyst@example.test",
        display_name="Analyst",
        source=UserSource.MANUAL,
        is_active=active,
    )


def make_session(
    user: User,
    *,
    expires_at: datetime = NOW + timedelta(hours=12),
    idle_expires_at: datetime = NOW + timedelta(hours=1),
    revoked_at: datetime | None = None,
) -> Session:
    return Session(
        id_hash=hashlib.sha256(b"x" * 43).digest(),
        user_id=user.id,
        created_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
        last_seen_at=NOW - timedelta(minutes=5),
        idle_expires_at=idle_expires_at,
        ip_hash=b"i" * 32,
        ua_hash=b"u" * 32,
        revoked_at=revoked_at,
    )


@pytest.mark.anyio
async def test_issue_stores_only_a_digest_and_keyed_client_fingerprints() -> None:
    manager = make_manager()
    db = FakeAsyncSession()
    user_id = uuid.uuid4()

    issued = await manager.issue(
        db,  # type: ignore[arg-type]
        user_id=user_id,
        client_ip="2001:0db8::1",
        user_agent="Browser/1.0",
        now=NOW,
    )

    assert len(issued.token) == 43
    assert issued.token not in repr(issued)
    assert issued.expires_at == NOW + timedelta(hours=12)
    assert len(db.added) == 1
    session = db.added[0]
    assert isinstance(session, Session)
    assert session.user_id == user_id
    assert session.id_hash == hashlib.sha256(issued.token.encode("ascii")).digest()
    assert session.id_hash != issued.token.encode("ascii")
    assert session.idle_expires_at == NOW + timedelta(hours=1)
    assert (
        session.ip_hash
        == hmac.new(SESSION_SECRET.encode("utf-8"), b"2001:db8::1", hashlib.sha256).digest()
    )
    assert (
        session.ua_hash
        == hmac.new(SESSION_SECRET.encode("utf-8"), b"Browser/1.0", hashlib.sha256).digest()
    )
    db.flush.assert_awaited_once()


@pytest.mark.anyio
async def test_verify_slides_idle_expiry_without_extending_absolute_expiry() -> None:
    manager = make_manager(idle_seconds=60 * 60, absolute_seconds=12 * 60 * 60)
    user = make_user()
    session = make_session(
        user,
        expires_at=NOW + timedelta(minutes=10),
        idle_expires_at=NOW + timedelta(minutes=1),
    )
    db = FakeAsyncSession(result=FakeResult(row=(session, user)))
    token = "x" * 43

    verified = await manager.verify(db, token=token, now=NOW)

    assert verified is not None
    assert verified.user is user
    assert verified.expires_at == NOW + timedelta(minutes=10)
    assert session.last_seen_at == NOW
    assert session.idle_expires_at == NOW + timedelta(minutes=10)
    assert "FOR UPDATE" in str(db.execute_calls[0])
    db.flush.assert_awaited_once()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "user_active, expires_at, idle_expires_at, revoked_at",
    [
        (False, NOW + timedelta(hours=1), NOW + timedelta(hours=1), None),
        (True, NOW, NOW + timedelta(hours=1), None),
        (True, NOW + timedelta(hours=1), NOW, None),
        (True, NOW + timedelta(hours=1), NOW + timedelta(hours=1), NOW),
    ],
)
async def test_verify_rejects_inactive_revoked_idle_and_absolute_expired_sessions(
    user_active: bool,
    expires_at: datetime,
    idle_expires_at: datetime,
    revoked_at: datetime | None,
) -> None:
    manager = make_manager()
    user = make_user(active=user_active)
    session = make_session(
        user,
        expires_at=expires_at,
        idle_expires_at=idle_expires_at,
        revoked_at=revoked_at,
    )
    db = FakeAsyncSession(result=FakeResult(row=(session, user)))

    assert await manager.verify(db, token="x" * 43, now=NOW) is None
    db.flush.assert_not_awaited()


@pytest.mark.anyio
async def test_verify_rejects_malformed_tokens_without_a_database_query() -> None:
    db = FakeAsyncSession()
    malformed_value = "not-a-token"

    assert await make_manager().verify(db, token=malformed_value, now=NOW) is None  # type: ignore[arg-type]
    assert db.execute_calls == []


@pytest.mark.anyio
async def test_revoke_is_idempotent() -> None:
    user = make_user()
    session = make_session(user)
    db = FakeAsyncSession(result=FakeResult(scalar=session))

    assert await make_manager().revoke(db, token="x" * 43, now=NOW) is True  # type: ignore[arg-type]
    assert session.revoked_at == NOW
    assert "FOR UPDATE" in str(db.execute_calls[0])
    db.flush.assert_awaited_once()

    assert await make_manager().revoke(db, token="x" * 43, now=NOW) is False  # type: ignore[arg-type]
    assert db.flush.await_count == 1


@pytest.mark.anyio
async def test_revoke_all_revokes_every_active_session() -> None:
    db = FakeAsyncSession(result=FakeResult(rowcount=3))

    changed = await make_manager().revoke_all(db, user_id=uuid.uuid4(), now=NOW)  # type: ignore[arg-type]

    assert changed == 3
    assert "revoked_at IS NULL" in str(db.execute_calls[0])
    db.flush.assert_awaited_once()


def test_session_cookie_is_secure_host_only_and_http_only() -> None:
    manager = make_manager()
    response = Response()
    issued = IssuedSession(token="x" * 43, expires_at=NOW + timedelta(hours=12))

    manager.set_cookie(response, issued, now=NOW)

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE_NAME}={'x' * 43}; ")
    assert "HttpOnly" in cookie
    assert "Max-Age=43200" in cookie
    assert "Path=/" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" in cookie
    assert "Domain=" not in cookie


def test_clear_cookie_uses_the_same_secure_scope() -> None:
    response = Response()

    make_manager().clear_cookie(response)

    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f'{SESSION_COOKIE_NAME}=""; ')
    assert "HttpOnly" in cookie
    assert "Path=/" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" in cookie
