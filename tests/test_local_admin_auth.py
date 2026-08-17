"""Offline verification for local super-admin provisioning and authentication controls."""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import pytest
from argon2 import PasswordHasher
from fastapi import Response
from sqlalchemy.dialects import postgresql

from app.auth.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from app.auth.local import (
    LocalAuthenticationError,
    LocalAuthenticationResult,
    LocalAuthenticator,
    SuperAdminAlreadyExistsError,
    build_totp_provisioning_uri,
    create_superadmin,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    hash_password,
    totp_code,
)
from app.auth.session import IssuedSession
from app.config import Settings
from app.create_superadmin import build_argument_parser
from app.db import get_db_session
from app.main import create_app
from app.models import AdminCredential, AdminLoginRateLimit, User, UserRole, UserSource

NOW = datetime(2026, 8, 15, 12, tzinfo=UTC)
TEST_PASSWORD = "a" * 20


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "postgresql+asyncpg://runtime:password@postgres/leakcheck",
        "session_secret": "s" * 32,
        "google_client_id": "portal-client-id.apps.googleusercontent.com",
        "google_client_secret": "c" * 32,
        "google_redirect_uri": "https://portal.example.test/auth/google/callback",
        "google_workspace_domains": ("example.test",),
        "data_key": base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        "trusted_hosts": ("portal.example.test",),
        "admin_login_max_failures": 2,
        "admin_login_lockout_seconds": 60,
        "admin_login_ip_max_failures": 4,
        "admin_login_ip_window_seconds": 60,
        "admin_login_ip_lockout_seconds": 60,
    }
    values.update(overrides)
    return Settings(**values)


@dataclass
class FakeResult:
    scalar: object | None = None
    row: tuple[User, AdminCredential] | None = None

    def scalar_one_or_none(self) -> object | None:
        return self.scalar

    def scalar_one(self) -> object:
        assert self.scalar is not None
        return self.scalar

    def one_or_none(self) -> tuple[User, AdminCredential] | None:
        return self.row


@dataclass
class FakeAsyncSession:
    rate_limit: AdminLoginRateLimit
    account_row: tuple[User, AdminCredential] | None = None
    existing_user: User | None = None
    added: list[object] = field(default_factory=list)
    execute_calls: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def execute(self, statement: object) -> FakeResult:
        self.execute_calls.append(statement)
        compiled = str(statement.compile(dialect=postgresql.dialect()))
        if compiled.startswith("INSERT INTO admin_login_rate_limits"):
            return FakeResult()
        if "FROM admin_login_rate_limits" in compiled:
            return FakeResult(scalar=self.rate_limit)
        if "JOIN admin_credentials" in compiled:
            return FakeResult(row=self.account_row)
        return FakeResult(scalar=self.existing_user)


def make_rate_limit(*, now: datetime = NOW) -> AdminLoginRateLimit:
    return AdminLoginRateLimit(ip_hash=b"i" * 32, window_started_at=now, attempts=0)


def make_account(settings: Settings) -> tuple[User, AdminCredential, str]:
    user = User(
        id=uuid.uuid4(),
        email="admin@example.test",
        display_name="SOC Admin",
        role=UserRole.SUPER_ADMIN,
        is_active=True,
        source=UserSource.MANUAL,
    )
    secret = generate_totp_secret()
    credential = AdminCredential(
        user_id=user.id,
        password_hash=hash_password(TEST_PASSWORD),
        totp_secret_enc=encrypt_totp_secret(settings, user_id=user.id, secret=secret),
        failed_attempts=0,
    )
    return user, credential, secret


def test_argon2id_hash_and_rfc6238_totp_are_used() -> None:
    password_hash = hash_password(TEST_PASSWORD)

    assert password_hash.startswith("$argon2id$")
    assert PasswordHasher().verify(password_hash, TEST_PASSWORD) is True
    # RFC 6238 Appendix B: the six-digit reduction of the SHA-1 value at 59 seconds.
    rfc_seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_code(rfc_seed, now=datetime(1970, 1, 1, 0, 0, 59, tzinfo=UTC)) == "287082"


def test_totp_storage_is_encrypted_and_bound_to_its_user() -> None:
    settings = make_settings()
    user_id = uuid.uuid4()
    secret = generate_totp_secret()
    encrypted = encrypt_totp_secret(settings, user_id=user_id, secret=secret)

    assert encrypted != secret.encode("ascii")
    assert decrypt_totp_secret(settings, user_id=user_id, encrypted=encrypted) == secret
    with pytest.raises(LocalAuthenticationError):
        decrypt_totp_secret(settings, user_id=uuid.uuid4(), encrypted=encrypted)
    with pytest.raises(LocalAuthenticationError):
        decrypt_totp_secret(settings, user_id=user_id, encrypted=encrypted[:-1] + b"x")


@pytest.mark.anyio
async def test_create_superadmin_is_manual_argon2id_and_totp_seeded() -> None:
    settings = make_settings()
    db = FakeAsyncSession(rate_limit=make_rate_limit())

    created = await create_superadmin(
        db,  # type: ignore[arg-type]
        settings=settings,
        email="ADMIN@example.test",
        display_name=" SOC Admin ",
        password=TEST_PASSWORD,
    )

    user = next(item for item in db.added if isinstance(item, User))
    credential = next(item for item in db.added if isinstance(item, AdminCredential))
    assert user is created.user
    assert user.email == "admin@example.test"
    assert user.role is UserRole.SUPER_ADMIN
    assert user.source is UserSource.MANUAL
    assert credential.password_hash.startswith("$argon2id$")
    assert PasswordHasher().verify(credential.password_hash, TEST_PASSWORD) is True
    assert decrypt_totp_secret(settings, user_id=user.id, encrypted=credential.totp_secret_enc) == (
        created.totp_secret
    )
    assert created.totp_secret not in repr(created)
    db.flush.assert_awaited_once()

    uri = build_totp_provisioning_uri(email=user.email, secret=created.totp_secret)
    parsed = urlsplit(uri)
    assert parsed.scheme == "otpauth"
    assert unquote(parsed.path) == "/LeakCheck SOC Portal:admin@example.test"
    assert parse_qs(parsed.query) == {
        "issuer": ["LeakCheck SOC Portal"],
        "secret": [created.totp_secret],
    }


@pytest.mark.anyio
async def test_create_superadmin_refuses_to_modify_an_existing_user() -> None:
    settings = make_settings()
    existing, _, _ = make_account(settings)
    db = FakeAsyncSession(rate_limit=make_rate_limit(), existing_user=existing)

    with pytest.raises(SuperAdminAlreadyExistsError):
        await create_superadmin(
            db,  # type: ignore[arg-type]
            settings=settings,
            email=existing.email,
            display_name="SOC Admin",
            password=TEST_PASSWORD,
        )

    assert db.added == []
    db.flush.assert_not_awaited()


@pytest.mark.anyio
async def test_local_login_requires_both_factors_and_resets_after_lockout_expiry() -> None:
    settings = make_settings()
    user, credential, secret = make_account(settings)
    rate_limit = make_rate_limit()
    db = FakeAsyncSession(rate_limit=rate_limit, account_row=(user, credential))
    authenticator = LocalAuthenticator(settings)

    for seconds in (0, 1):
        failed = await authenticator.authenticate(
            db,  # type: ignore[arg-type]
            username=user.email,
            password=TEST_PASSWORD,
            totp_code="000000",
            client_ip="2001:db8::1",
            now=NOW + timedelta(seconds=seconds),
        )
        assert failed.user is None

    assert credential.failed_attempts == 2
    assert credential.locked_until == NOW + timedelta(seconds=61)
    locked = await authenticator.authenticate(
        db,  # type: ignore[arg-type]
        username=user.email,
        password=TEST_PASSWORD,
        totp_code=totp_code(secret, now=NOW + timedelta(seconds=2)),
        client_ip="2001:db8::1",
        now=NOW + timedelta(seconds=2),
    )
    assert locked.user is None

    after_lockout = NOW + timedelta(seconds=62)
    authenticated = await authenticator.authenticate(
        db,  # type: ignore[arg-type]
        username=user.email,
        password=TEST_PASSWORD,
        totp_code=totp_code(secret, now=after_lockout),
        client_ip="2001:db8::1",
        now=after_lockout,
    )
    assert authenticated.user is user
    assert credential.failed_attempts == 0
    assert credential.locked_until is None
    assert user.last_login_at == after_lockout
    assert rate_limit.attempts == 0


@pytest.mark.anyio
async def test_unknown_accounts_use_the_durable_keyed_ip_throttle() -> None:
    settings = make_settings(admin_login_ip_max_failures=2)
    rate_limit = make_rate_limit()
    db = FakeAsyncSession(rate_limit=rate_limit)
    authenticator = LocalAuthenticator(settings)

    for seconds in (0, 1):
        outcome = await authenticator.authenticate(
            db,  # type: ignore[arg-type]
            username="missing@example.test",
            password=TEST_PASSWORD,
            totp_code="000000",
            client_ip="192.0.2.1",
            now=NOW + timedelta(seconds=seconds),
        )
        assert outcome.user is None

    assert rate_limit.attempts == 2
    assert rate_limit.blocked_until == NOW + timedelta(seconds=61)
    assert any(
        "FOR UPDATE" in str(statement.compile(dialect=postgresql.dialect()))
        for statement in db.execute_calls
    )
    assert all(
        b"192.0.2.1" not in str(statement.compile(dialect=postgresql.dialect())).encode()
        for statement in db.execute_calls
    )

    calls_before_blocked_retry = len(db.execute_calls)
    blocked = await authenticator.authenticate(
        db,  # type: ignore[arg-type]
        username="missing@example.test",
        password=TEST_PASSWORD,
        totp_code="000000",
        client_ip="192.0.2.1",
        now=NOW + timedelta(seconds=2),
    )
    assert blocked.user is None
    assert len(db.execute_calls) == calls_before_blocked_retry + 2


def test_cli_has_no_password_argument() -> None:
    parser = build_argument_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--password", TEST_PASSWORD])


class FakeRouteAuthenticator:
    def __init__(self, result: LocalAuthenticationResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    async def authenticate(self, db: object, **kwargs: object) -> LocalAuthenticationResult:
        del db
        self.calls.append(kwargs)
        return self.result


class FakeRouteSessionManager:
    def __init__(self) -> None:
        self.revoke_calls: list[str | None] = []
        self.issue_calls: list[dict[str, object]] = []

    async def revoke(self, db: object, *, token: str | None) -> bool:
        del db
        self.revoke_calls.append(token)
        return True

    async def issue(self, db: object, **kwargs: object) -> IssuedSession:
        del db
        self.issue_calls.append(kwargs)
        return IssuedSession(token="x" * 43, expires_at=NOW + timedelta(hours=1))

    def set_cookie(self, response: Response, issued: IssuedSession) -> None:
        response.set_cookie(
            key="__Host-leakcheck-session",
            value=issued.token,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )


@pytest.mark.anyio
async def test_local_login_route_rotates_session_without_reflecting_credentials() -> None:
    settings = make_settings()
    user, _, _ = make_account(settings)
    app = create_app(settings)
    authenticator = FakeRouteAuthenticator(LocalAuthenticationResult(user=user))
    session_manager = FakeRouteSessionManager()
    app.state.local_authenticator = authenticator
    app.state.session_manager = session_manager

    async def fake_db_dependency() -> object:
        yield FakeAsyncSession(rate_limit=make_rate_limit())

    app.dependency_overrides[get_db_session] = fake_db_dependency
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://portal.example.test",
        follow_redirects=False,
    ) as client:
        csrf_response = await client.get("/auth/csrf")
        csrf_token = csrf_response.cookies.get(CSRF_COOKIE_NAME)
        response = await client.post(
            "/auth/local/login",
            json={"username": user.email, "password": TEST_PASSWORD, "totp_code": "123456"},
            headers={CSRF_HEADER_NAME: csrf_token},
        )
        rotated_csrf_token = response.cookies.get(CSRF_COOKIE_NAME)

    assert csrf_response.status_code == 204
    assert csrf_token is not None
    assert rotated_csrf_token is not None
    assert rotated_csrf_token != csrf_token
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    assert response.headers["cache-control"] == "no-store"
    assert authenticator.calls[0]["password"] == TEST_PASSWORD
    assert session_manager.issue_calls[0]["user_id"] == user.id
    assert TEST_PASSWORD not in response.text


@pytest.mark.anyio
async def test_local_login_route_returns_one_non_reflecting_failure_for_bad_payload() -> None:
    settings = make_settings()
    app = create_app(settings)
    authenticator = FakeRouteAuthenticator(LocalAuthenticationResult(user=None))
    app.state.local_authenticator = authenticator

    async def fake_db_dependency() -> object:
        yield FakeAsyncSession(rate_limit=make_rate_limit())

    app.dependency_overrides[get_db_session] = fake_db_dependency

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://portal.example.test"
    ) as client:
        csrf_response = await client.get("/auth/csrf")
        csrf_token = csrf_response.cookies.get(CSRF_COOKIE_NAME)
        response = await client.post(
            "/auth/local/login",
            json={"username": "admin@example.test", "password": TEST_PASSWORD, "totp_code": 123456},
            headers={CSRF_HEADER_NAME: csrf_token},
        )

    assert csrf_response.status_code == 204
    assert csrf_token is not None
    assert response.status_code == 401
    assert response.text == "Local authentication failed."
    assert response.headers["cache-control"] == "no-store"
    assert authenticator.calls == []
    assert TEST_PASSWORD not in response.text
