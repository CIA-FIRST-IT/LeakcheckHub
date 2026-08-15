"""Public authentication endpoints.  Protected portal routes arrive in M1-05."""

from __future__ import annotations

import hmac
import json
from datetime import UTC, datetime
from typing import cast

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.google import (
    OAUTH_TRANSACTION_COOKIE_NAME,
    GoogleOIDC,
    GoogleOIDCError,
    provision_google_user,
)
from app.auth.local import LocalAuthenticationResult, LocalAuthenticator
from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.db import get_db_session

router = APIRouter(include_in_schema=False)
_MAX_LOCAL_LOGIN_BODY_BYTES = 4096


async def get_google_oidc(request: Request) -> GoogleOIDC:
    """Read the per-app OIDC client, retaining its discovery and JWKS caches."""

    return cast(GoogleOIDC, request.app.state.google_oidc)


async def get_session_manager_for_request(request: Request) -> SessionManager:
    """Read the per-app session manager configured with the matching secret."""

    return cast(SessionManager, request.app.state.session_manager)


async def get_local_authenticator(request: Request) -> LocalAuthenticator:
    """Read the per-app local authentication service with its matching security settings."""

    return cast(LocalAuthenticator, request.app.state.local_authenticator)


@router.get("/auth/google/login", response_model=None)
async def start_google_login(
    google_oidc: GoogleOIDC = Depends(get_google_oidc),  # noqa: B008
) -> RedirectResponse | PlainTextResponse:
    """Start a code-only Google login after binding state, nonce, and PKCE to one browser."""

    transaction = google_oidc.begin_transaction()
    try:
        authorization_url = await google_oidc.authorization_url(transaction)
    except GoogleOIDCError:
        return _authentication_failed(status_code=503)
    response = RedirectResponse(authorization_url, status_code=303)
    response.set_cookie(
        key=OAUTH_TRANSACTION_COOKIE_NAME,
        value=google_oidc.transaction_cookie(transaction),
        max_age=int(transaction.expires_at - int(datetime.now(UTC).timestamp())),
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/auth/google/callback", response_model=None)
async def finish_google_login(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    google_oidc: GoogleOIDC = Depends(get_google_oidc),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse | PlainTextResponse:
    """Exchange and validate a Google code, then provision and issue a rotated portal session."""

    transaction = google_oidc.read_transaction_cookie(
        request.cookies.get(OAUTH_TRANSACTION_COOKIE_NAME)
    )
    if (
        error is not None
        or transaction is None
        or state is None
        or code is None
        or not state.isascii()
        or len(state) != len(transaction.state)
        or not hmac.compare_digest(state.encode("ascii"), transaction.state.encode("ascii"))
        or request.client is None
    ):
        return _authentication_failed()
    try:
        identity = await google_oidc.exchange_and_verify(code, transaction)
        user = await provision_google_user(db, identity)
        if not user.is_active:
            return _authentication_failed(status_code=403)
        await session_manager.revoke(db, token=request.cookies.get(SESSION_COOKIE_NAME))
        issued = await session_manager.issue(
            db,
            user_id=user.id,
            client_ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
        )
        user.last_login_at = datetime.now(UTC)
        await db.flush()
    except GoogleOIDCError:
        return _authentication_failed()

    response = RedirectResponse("/", status_code=303)
    session_manager.set_cookie(response, issued)
    _clear_transaction_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/auth/local/login", response_model=None)
async def finish_local_login(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    local_authenticator: LocalAuthenticator = Depends(get_local_authenticator),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
) -> RedirectResponse | PlainTextResponse:
    """Complete password-and-TOTP login without reflecting any submitted credential material."""

    credentials = await _read_local_login_credentials(request)
    if credentials is None or request.client is None:
        return _local_authentication_failed()
    username, password, totp_code = credentials
    authenticated: LocalAuthenticationResult = await local_authenticator.authenticate(
        db,
        username=username,
        password=password,
        totp_code=totp_code,
        client_ip=request.client.host,
    )
    if authenticated.user is None:
        return _local_authentication_failed()

    await session_manager.revoke(db, token=request.cookies.get(SESSION_COOKIE_NAME))
    issued = await session_manager.issue(
        db,
        user_id=authenticated.user.id,
        client_ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )
    response = RedirectResponse("/", status_code=303)
    session_manager.set_cookie(response, issued)
    response.headers["Cache-Control"] = "no-store"
    return response


def _authentication_failed(*, status_code: int = 400) -> PlainTextResponse:
    """Return a generic error that neither leaks provider details nor preserves login state."""

    response = PlainTextResponse("Google authentication failed.", status_code=status_code)
    _clear_transaction_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return response


async def _read_local_login_credentials(request: Request) -> tuple[str, str, str] | None:
    """Read a tiny JSON credential body without exposing Pydantic validation echoes to a caller."""

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _MAX_LOCAL_LOGIN_BODY_BYTES:
                return None
        except ValueError:
            return None
    body = await request.body()
    if len(body) > _MAX_LOCAL_LOGIN_BODY_BYTES:
        return None
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) != {"username", "password", "totp_code"}:
        return None
    username = payload["username"]
    password = payload["password"]
    totp_code = payload["totp_code"]
    try:
        password_length = len(password.encode("utf-8")) if isinstance(password, str) else 0
    except UnicodeEncodeError:
        return None
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not isinstance(totp_code, str)
        or len(username) > 255
        or password_length > 1024
        or len(totp_code) > 16
    ):
        return None
    return username, password, totp_code


def _local_authentication_failed() -> PlainTextResponse:
    """Return one cache-proof response for every local credential or throttle failure."""

    response = PlainTextResponse("Local authentication failed.", status_code=401)
    response.headers["Cache-Control"] = "no-store"
    return response


def _clear_transaction_cookie(response: PlainTextResponse | RedirectResponse) -> None:
    response.delete_cookie(
        key=OAUTH_TRANSACTION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
