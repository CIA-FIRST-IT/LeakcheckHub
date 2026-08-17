"""Public authentication endpoints.  Protected portal routes arrive in M1-05."""

from __future__ import annotations

import hmac
import html
import json
from datetime import UTC, datetime
from typing import cast

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from app.audit import audit_event
from app.auth.authorization import get_session_manager_for_request, require_role
from app.auth.csrf import CSRFProtector
from app.auth.google import (
    OAUTH_TRANSACTION_COOKIE_NAME,
    GoogleOIDC,
    GoogleOIDCConfiguration,
    GoogleOIDCError,
    provision_google_user,
)
from app.auth.local import (
    LocalAuthenticationError,
    LocalAuthenticationResult,
    LocalAuthenticator,
    build_totp_provisioning_uri,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    verify_totp,
)
from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.db import get_db_session
from app.models import AdminCredential, User, UserRole
from app.platform_settings import PlatformSettingsStore, SettingKey

router = APIRouter(include_in_schema=False)
_MAX_LOCAL_LOGIN_BODY_BYTES = 4096
_ALL_ROLES_GUARD = require_role(UserRole.USER, UserRole.ANALYST, UserRole.SUPER_ADMIN)


async def get_google_oidc(
    request: Request,
) -> GoogleOIDC | None:
    """Return a process-cached legacy client, if an existing deployment supplied one."""

    cached = request.app.state.google_oidc
    if cached is not None:
        return cast(GoogleOIDC, cached)
    return None


async def _configured_google_oidc(
    request: Request, db: AsyncSession, cached: GoogleOIDC | None
) -> GoogleOIDC | None:
    """Resolve encrypted database configuration only when no cached legacy client exists."""

    if cached is not None:
        return cached
    return await _load_google_oidc(request, db)


async def _load_google_oidc(request: Request, db: AsyncSession) -> GoogleOIDC | None:
    store = cast(PlatformSettingsStore, request.app.state.platform_settings)
    keys = {
        SettingKey.GOOGLE_CLIENT_ID,
        SettingKey.GOOGLE_CLIENT_SECRET,
        SettingKey.GOOGLE_REDIRECT_URI,
        SettingKey.GOOGLE_WORKSPACE_DOMAINS,
    }
    values = await store.read_many(db, keys)
    if keys - values.keys():
        return None
    configuration = GoogleOIDCConfiguration(
        client_id=values[SettingKey.GOOGLE_CLIENT_ID],
        client_secret=values[SettingKey.GOOGLE_CLIENT_SECRET],
        redirect_uri=values[SettingKey.GOOGLE_REDIRECT_URI],
        allowed_domains=store.decode_domains(values[SettingKey.GOOGLE_WORKSPACE_DOMAINS]),
    )
    return GoogleOIDC(request.app.state.settings, configuration=configuration)


async def get_local_authenticator(request: Request) -> LocalAuthenticator:
    """Read the per-app local authentication service with its matching security settings."""

    return cast(LocalAuthenticator, request.app.state.local_authenticator)


async def get_csrf_protector(request: Request) -> CSRFProtector:
    """Read the CSRF issuer configured with the matching session-secret-derived key."""

    return cast(CSRFProtector, request.app.state.csrf_protector)


@router.get("/", response_model=None)
async def landing_page(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
) -> HTMLResponse | RedirectResponse:
    """Show the login page or send an existing session to its role-specific home."""

    verified = await session_manager.verify(db, token=request.cookies.get(SESSION_COOKIE_NAME))
    if verified is not None:
        destinations = {
            UserRole.SUPER_ADMIN: "/admin/settings",
            UserRole.ANALYST: "/analyst",
            UserRole.USER: "/portal",
        }
        return RedirectResponse(destinations[verified.user.role], status_code=303)
    return HTMLResponse(
        """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>LeakCheck sign in</title></head>
<body><main><h1>LeakCheck sign in</h1>
<form id="local-login"><label>Email
<input name="username" type="email" autocomplete="username" required></label>
<label>Password
<input name="password" type="password" autocomplete="current-password" required></label>
<label>Authenticator code
<input name="totp_code" inputmode="numeric" autocomplete="one-time-code"></label>
<p>Leave the authenticator code blank until MFA has been enabled for this account.</p>
<button type="submit">Sign in</button></form>
<p><a href="/auth/google/login">Sign in with Google</a></p>
<output id="login-result"></output><script src="/static/login.js" defer></script>
</main></body></html>""",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/auth/csrf", response_model=None)
async def issue_csrf_token(
    request: Request,
    csrf_protector: CSRFProtector = Depends(get_csrf_protector),  # noqa: B008
) -> Response:
    """Set a token readable by same-origin browser code before an unsafe request."""

    response = Response(status_code=204)
    csrf_protector.issue(response, session_token=request.cookies.get(SESSION_COOKIE_NAME))
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/auth/google/login", response_model=None)
async def start_google_login(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    google_oidc: GoogleOIDC | None = Depends(get_google_oidc),  # noqa: B008
) -> RedirectResponse | PlainTextResponse:
    """Start a code-only Google login after binding state, nonce, and PKCE to one browser."""

    google_oidc = await _configured_google_oidc(request, db, google_oidc)
    if google_oidc is None:
        await audit_event(
            db,
            request,
            request.app.state.settings,
            action="auth.google_failed",
            meta={"reason": "unconfigured"},
        )
        return _authentication_failed(status_code=503)
    transaction = google_oidc.begin_transaction()
    try:
        authorization_url = await google_oidc.authorization_url(transaction)
    except GoogleOIDCError:
        await audit_event(db, request, request.app.state.settings, action="auth.google_failed")
        return _authentication_failed(status_code=503)
    await audit_event(db, request, request.app.state.settings, action="auth.google_started")
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
    google_oidc: GoogleOIDC | None = Depends(get_google_oidc),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
    csrf_protector: CSRFProtector = Depends(get_csrf_protector),  # noqa: B008
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse | PlainTextResponse:
    """Exchange and validate a Google code, then provision and issue a rotated portal session."""

    google_oidc = await _configured_google_oidc(request, db, google_oidc)
    if google_oidc is None:
        await audit_event(
            db,
            request,
            request.app.state.settings,
            action="auth.google_failed",
            meta={"reason": "unconfigured"},
        )
        return _authentication_failed(status_code=503)
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
        await audit_event(db, request, request.app.state.settings, action="auth.google_failed")
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
        await audit_event(
            db,
            request,
            request.app.state.settings,
            action="auth.google_succeeded",
            actor_id=user.id,
            target_type="user",
            target_id=str(user.id),
        )
        await db.flush()
    except GoogleOIDCError:
        await audit_event(db, request, request.app.state.settings, action="auth.google_failed")
        return _authentication_failed()

    response = RedirectResponse("/", status_code=303)
    session_manager.set_cookie(response, issued)
    csrf_protector.issue(response, session_token=issued.token)
    _clear_transaction_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/auth/local/login", response_model=None)
async def finish_local_login(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    local_authenticator: LocalAuthenticator = Depends(get_local_authenticator),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
    csrf_protector: CSRFProtector = Depends(get_csrf_protector),  # noqa: B008
) -> RedirectResponse | PlainTextResponse:
    """Complete password-and-TOTP login without reflecting any submitted credential material."""

    credentials = await _read_local_login_credentials(request)
    if credentials is None or request.client is None:
        await audit_event(db, request, request.app.state.settings, action="auth.local_failed")
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
        await audit_event(db, request, request.app.state.settings, action="auth.local_failed")
        return _local_authentication_failed()

    await session_manager.revoke(db, token=request.cookies.get(SESSION_COOKIE_NAME))
    issued = await session_manager.issue(
        db,
        user_id=authenticated.user.id,
        client_ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )
    authenticated.user.last_login_at = datetime.now(UTC)
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="auth.local_succeeded",
        actor_id=authenticated.user.id,
        target_type="user",
        target_id=str(authenticated.user.id),
    )
    response = RedirectResponse("/", status_code=303)
    session_manager.set_cookie(response, issued)
    csrf_protector.issue(response, session_token=issued.token)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/account/mfa", response_model=None)
async def mfa_setup_page(
    request: Request,
    current_user: User = Depends(_ALL_ROLES_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    """Create or resume a pending TOTP enrollment for a local administrator."""

    result = await db.execute(
        select(AdminCredential)
        .options(undefer(AdminCredential.totp_secret_enc))
        .where(AdminCredential.user_id == current_user.id)
        .with_for_update()
    )
    credential = result.scalar_one_or_none()
    if credential is None:
        return HTMLResponse("MFA is managed by your sign-in provider.", status_code=400)
    if credential.totp_enabled_at is not None:
        return HTMLResponse(
            "<!doctype html><html><body><main><h1>Account security</h1>"
            '<p>MFA is enabled for this account.</p><p><a href="/">Return to LeakCheck</a></p>'
            "</main></body></html>",
            headers={"Cache-Control": "no-store"},
        )
    try:
        if credential.totp_secret_enc is None:
            secret = generate_totp_secret()
            credential.totp_secret_enc = encrypt_totp_secret(
                request.app.state.settings, user_id=current_user.id, secret=secret
            )
            await db.flush()
        else:
            secret = decrypt_totp_secret(
                request.app.state.settings,
                user_id=current_user.id,
                encrypted=credential.totp_secret_enc,
            )
    except LocalAuthenticationError:
        return HTMLResponse("MFA setup could not be initialized.", status_code=500)
    uri = build_totp_provisioning_uri(email=current_user.email, secret=secret)
    return HTMLResponse(
        "".join(
            (
                "<!doctype html><html><body><main><h1>Set up MFA</h1>",
                "<p>Add this account to your authenticator, then enter a generated code "
                "to enable MFA.</p>",
                f'<p><a href="{html.escape(uri, quote=True)}">Open in authenticator</a></p>',
                f"<p>Manual setup key: <code>{html.escape(secret)}</code></p>",
                '<form id="mfa-form"><label>Authenticator code <input name="totp_code" ',
                'inputmode="numeric" autocomplete="one-time-code" required></label>',
                '<button type="submit">Enable MFA</button></form><output id="mfa-result"></output>',
                '<script src="/static/mfa-setup.js" defer></script></main></body></html>',
            )
        ),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/account/mfa/enable", response_model=None)
async def enable_mfa(
    request: Request,
    current_user: User = Depends(_ALL_ROLES_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> JSONResponse:
    """Enable a pending seed only after the signed-in user proves possession."""

    code = await _read_mfa_code(request)
    result = await db.execute(
        select(AdminCredential)
        .options(undefer(AdminCredential.totp_secret_enc))
        .where(AdminCredential.user_id == current_user.id)
        .with_for_update()
    )
    credential = result.scalar_one_or_none()
    if credential is None or credential.totp_secret_enc is None or code is None:
        return JSONResponse({"detail": "MFA setup is not ready."}, status_code=400)
    try:
        secret = decrypt_totp_secret(
            request.app.state.settings,
            user_id=current_user.id,
            encrypted=credential.totp_secret_enc,
        )
    except LocalAuthenticationError:
        return JSONResponse({"detail": "MFA setup is not ready."}, status_code=400)
    if not verify_totp(secret, code):
        return JSONResponse({"detail": "The authenticator code was not accepted."}, status_code=422)
    credential.totp_enabled_at = datetime.now(UTC)
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="auth.mfa_enabled",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(current_user.id),
    )
    await db.flush()
    return JSONResponse({"enabled": True})


@router.post("/auth/logout", response_model=None)
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
    current_user: User = Depends(_ALL_ROLES_GUARD),  # noqa: B008
) -> Response:
    """Revoke the active server-side session and clear its browser credential."""

    await session_manager.revoke(db, token=request.cookies.get(SESSION_COOKIE_NAME))
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="auth.logout",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(current_user.id),
    )
    response = Response(status_code=204)
    session_manager.clear_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return response


def _authentication_failed(*, status_code: int = 400) -> PlainTextResponse:
    """Return a generic error that neither leaks provider details nor preserves login state."""

    response = PlainTextResponse("Google authentication failed.", status_code=status_code)
    _clear_transaction_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return response


async def _read_local_login_credentials(request: Request) -> tuple[str, str, str | None] | None:
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
    if (
        not isinstance(payload, dict)
        or not {"username", "password"} <= set(payload)
        or set(payload)
        - {
            "username",
            "password",
            "totp_code",
        }
    ):
        return None
    username = payload["username"]
    password = payload["password"]
    totp_code = payload.get("totp_code") or None
    try:
        password_length = len(password.encode("utf-8")) if isinstance(password, str) else 0
    except UnicodeEncodeError:
        return None
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or (totp_code is not None and not isinstance(totp_code, str))
        or len(username) > 255
        or password_length > 1024
        or (totp_code is not None and len(totp_code) > 16)
    ):
        return None
    return username, password, totp_code


async def _read_mfa_code(request: Request) -> str | None:
    try:
        payload = json.loads(await request.body())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) != {"totp_code"}:
        return None
    code = payload["totp_code"]
    return code if isinstance(code, str) and len(code) <= 16 else None


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
