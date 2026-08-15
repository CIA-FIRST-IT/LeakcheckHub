"""Offline tests for session role guards and signed double-submit CSRF protection."""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from app.auth.authorization import get_current_user, require_role
from app.auth.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, CSRFProtector
from app.auth.session import SESSION_COOKIE_NAME, VerifiedSession
from app.config import Settings
from app.main import create_app
from app.models import User, UserRole, UserSource

NOW = datetime(2026, 8, 15, 12, tzinfo=UTC)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        google_client_id="portal-client-id.apps.googleusercontent.com",
        google_client_secret="c" * 32,
        google_redirect_uri="https://portal.example.test/auth/google/callback",
        google_workspace_domains=("example.test",),
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("portal.example.test",),
    )


def make_user(role: UserRole) -> User:
    return User(
        id=uuid.uuid4(),
        email=f"{role.value}@example.test",
        display_name=role.value,
        role=role,
        source=UserSource.MANUAL,
    )


def make_request(*, session_token: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if session_token is not None:
        headers.append((b"cookie", f"{SESSION_COOKIE_NAME}={session_token}".encode("ascii")))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/protected",
            "raw_path": b"/protected",
            "query_string": b"",
            "headers": headers,
            "client": ("192.0.2.1", 1234),
            "server": ("portal.example.test", 443),
            "scheme": "https",
        }
    )


class FakeSessionManager:
    def __init__(self, verified: VerifiedSession | None) -> None:
        self.verified = verified
        self.tokens: list[str | None] = []

    async def verify(self, db: object, *, token: str | None) -> VerifiedSession | None:
        del db
        self.tokens.append(token)
        return self.verified


@pytest.mark.anyio
async def test_current_user_uses_only_an_active_server_side_session() -> None:
    user = make_user(UserRole.ANALYST)
    session_manager = FakeSessionManager(
        VerifiedSession(user=user, expires_at=NOW + timedelta(hours=1))
    )
    token = "x" * 43

    resolved = await get_current_user(
        make_request(session_token=token),
        db=object(),  # type: ignore[arg-type]
        session_manager=session_manager,  # type: ignore[arg-type]
    )

    assert resolved is user
    assert session_manager.tokens == [token]


@pytest.mark.anyio
async def test_current_user_rejects_a_missing_or_invalid_session() -> None:
    session_manager = FakeSessionManager(None)

    with pytest.raises(HTTPException) as error:
        await get_current_user(
            make_request(),
            db=object(),  # type: ignore[arg-type]
            session_manager=session_manager,  # type: ignore[arg-type]
        )

    assert error.value.status_code == 401
    assert error.value.headers == {"WWW-Authenticate": "Session"}
    assert session_manager.tokens == [None]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("role", "permitted"),
    [
        (UserRole.USER, False),
        (UserRole.ANALYST, True),
        (UserRole.SUPER_ADMIN, True),
    ],
)
async def test_require_role_enforces_the_role_matrix(role: UserRole, permitted: bool) -> None:
    guard = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
    user = make_user(role)

    if permitted:
        assert await guard(current_user=user) is user
    else:
        with pytest.raises(HTTPException) as error:
            await guard(current_user=user)
        assert error.value.status_code == 403


def test_require_role_rejects_an_empty_allow_list() -> None:
    with pytest.raises(ValueError, match="at least one"):
        require_role()


def test_csrf_token_is_signed_session_bound_and_host_only() -> None:
    protector = CSRFProtector(make_settings())
    response = Response()
    session_token = "x" * 43
    token = protector.issue(response, session_token=session_token)

    assert protector.valid(
        session_token=session_token,
        cookie_value=token,
        supplied_value=token,
    )
    assert not protector.valid(
        session_token="y" * 43,
        cookie_value=token,
        supplied_value=token,
    )
    assert not protector.valid(
        session_token=session_token,
        cookie_value=token,
        supplied_value="x" * len(token),
    )
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{CSRF_COOKIE_NAME}=")
    assert "Path=/" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" in cookie
    assert "HttpOnly" not in cookie
    assert "Domain=" not in cookie


@pytest.mark.anyio
async def test_csrf_middleware_rejects_unsafe_requests_without_a_matching_token() -> None:
    app = create_app(make_settings())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://portal.example.test"
    ) as client:
        health = await client.get("/healthz")
        missing = await client.post("/auth/local/login", json={})
        issued = await client.get("/auth/csrf")
        token = issued.cookies.get(CSRF_COOKIE_NAME)
        mismatched = await client.post(
            "/auth/local/login",
            json={},
            headers={CSRF_HEADER_NAME: "x" * 87},
        )

    assert health.status_code == 200
    assert missing.status_code == 403
    assert mismatched.status_code == 403
    assert missing.text == "CSRF validation failed."
    assert missing.headers["cache-control"] == "no-store"
    assert issued.status_code == 204
    assert token is not None
