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

from app import branding
from app.analyst_ui import page
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
    hash_password,
    verify_password,
    verify_totp,
)
from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.db import get_db_session
from app.models import AdminCredential, User, UserRole
from app.platform_settings import PlatformSettingsStore, SettingKey
from app.totp_qr import provisioning_qr_svg

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
    brand = await branding.load(db)
    name = html.escape(brand.display_name)
    logo = (
        f'<img class="org-logo" alt="{name}" '
        f'src="/branding/logo?v={html.escape(brand.logo_sha256 or "")}">'
        if brand.has_logo
        else '<div class="brand-mark" aria-hidden="true">LC</div>'
    )
    return HTMLResponse(
        "".join(
            (
                '<!doctype html><html lang="en"><head><meta charset="utf-8">',
                '<meta name="viewport" content="width=device-width,initial-scale=1">',
                f"<title>Sign in · {name}</title>",
                '<link rel="stylesheet" href="/static/auth.css?v=3"></head>',
                '<body class="auth-page landing"><main class="landing-shell">',
                f'<div class="org-identity">{logo}<p class="org-name">{name}</p></div>',
                "<h1>Sign in with Google to scan your email for leaked credentials.</h1>",
                '<a class="google-button primary" href="/auth/google/login">',
                '<span class="google-glyph" aria-hidden="true">G</span>',
                "Sign in with Google</a>",
                '<output id="login-result" class="form-status"></output>',
                "</main>",
                '<button type="button" id="admin-toggle" class="admin-corner" ',
                'aria-expanded="false" aria-controls="admin-login">Super Admin Sign In</button>',
                '<dialog id="admin-login" class="admin-dialog">',
                '<form id="local-login" class="auth-form" method="dialog">',
                "<h2>Super Admin Sign In</h2>",
                "<label>Email address",
                '<input name="username" type="email" autocomplete="username" required></label>',
                "<label>Password",
                '<input name="password" type="password" autocomplete="current-password" ',
                "required></label>",
                '<label>Authenticator code <span class="optional">Once MFA is enabled</span>',
                '<input name="totp_code" inputmode="numeric" autocomplete="one-time-code" ',
                'maxlength="6" placeholder="000000"></label>',
                '<div class="dialog-actions"><button type="submit">Sign in</button>',
                '<button type="button" id="admin-close">Cancel</button></div></form>',
                "</dialog>",
                '<script src="/static/login.js?v=3" defer></script></body></html>',
            )
        ),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/branding/logo", response_model=None)
async def branding_logo(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    """Serve the organisation logo. Public: it is rendered on the sign-in page."""

    stored = await branding.load_logo(db)
    if stored is None:
        return Response(status_code=404)
    data, content_type, digest = stored
    etag = f'"{digest}"' if digest else None
    if etag and request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    headers = {
        # Revalidate every time so a replaced logo appears immediately; the ETag keeps it cheap.
        "Cache-Control": "public, max-age=0, must-revalidate",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-Content-Type-Options": "nosniff",
    }
    if etag:
        headers["ETag"] = etag
    return Response(content=data, media_type=content_type, headers=headers)


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
            page(
                "Profile · MFA",
                '<section class="hero compact"><p class="eyebrow">Account security</p>'
                "<h1>MFA is enabled</h1><p>Your authenticator code is required at sign-in.</p>"
                '<a class="button secondary" href="/account/profile">Back to Profile</a></section>',
                user=current_user,
            ),
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
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Account security</p>',
            "<h1>Set up MFA</h1><p>Scan this code with your authenticator, then enter a generated ",
            'code to enable MFA.</p></section><section class="panel profile-panel">',
            # Inlined, never a URL: an enrollment secret must not be cacheable or land in a log.
            f'<figure class="totp-qr">{provisioning_qr_svg(uri)}</figure>',
            f'<p><a class="button secondary" href="{html.escape(uri, quote=True)}">',
            "Open in authenticator</a></p>",
            f"<p>Can't scan? Manual setup key: <code>{html.escape(secret)}</code></p>",
            '<form id="mfa-form"><label>Authenticator code <input name="totp_code" ',
            'inputmode="numeric" autocomplete="one-time-code" required></label>',
            '<button type="submit">Enable MFA</button></form><output id="mfa-result"></output>',
            "</section>",
        )
    )
    return HTMLResponse(
        page(
            "Profile · MFA",
            content,
            user=current_user,
            extra_scripts=("/static/mfa-setup.js?v=3",),
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


@router.get("/account/profile", response_model=None)
async def profile_page(
    current_user: User = Depends(_ALL_ROLES_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    """Render local administrator password and MFA controls."""

    credential = (
        await db.execute(select(AdminCredential).where(AdminCredential.user_id == current_user.id))
    ).scalar_one_or_none()
    if credential is None or current_user.role is not UserRole.SUPER_ADMIN:
        return HTMLResponse(
            "Profile security is managed by your sign-in provider.", status_code=400
        )
    mfa_status = "Enabled" if credential.totp_enabled_at is not None else "Not enabled"
    mfa_action = (
        '<span class="badge success">Enabled</span>'
        if credential.totp_enabled_at is not None
        else '<a class="button" href="/account/mfa">Enable MFA</a>'
    )
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Administrator account</p>',
            f"<h1>{html.escape(current_user.email)}</h1>",
            "<p>Manage the security controls for this local administrator.</p></section>",
            '<section class="profile-grid"><article class="panel profile-panel"><h2>MFA</h2>',
            f"<p>Status: {mfa_status}</p>{mfa_action}</article>",
            '<article class="panel profile-panel"><h2>Change password</h2>',
            '<form id="password-form"><label>Current password',
            '<input type="password" name="current_password" autocomplete="current-password" ',
            "required>",
            '</label><label>New password<input type="password" name="new_password" ',
            'autocomplete="new-password" minlength="15" required></label>',
            '<label>Confirm new password<input type="password" name="confirmation" ',
            'autocomplete="new-password" minlength="15" required></label>',
            '<button type="submit">Change password</button></form>',
            '<output id="profile-result" class="form-error"></output></article></section>',
        )
    )
    return HTMLResponse(
        page(
            "Profile",
            content,
            user=current_user,
            extra_scripts=("/static/profile.js?v=3",),
        ),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/account/profile/password", response_model=None)
async def change_password(
    request: Request,
    current_user: User = Depends(_ALL_ROLES_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> JSONResponse:
    """Change a local administrator password after verifying the current password."""

    body = await request.body()
    if len(body) > _MAX_LOCAL_LOGIN_BODY_BYTES:
        return JSONResponse({"detail": "Invalid password change request."}, status_code=400)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    required = {"current_password", "new_password", "confirmation"}
    if not isinstance(payload, dict) or set(payload) != required:
        return JSONResponse({"detail": "Invalid password change request."}, status_code=400)
    current_password = payload["current_password"]
    new_password = payload["new_password"]
    confirmation = payload["confirmation"]
    if not all(isinstance(value, str) for value in (current_password, new_password, confirmation)):
        return JSONResponse({"detail": "Invalid password change request."}, status_code=400)
    try:
        if any(
            len(value.encode("utf-8")) > 1024
            for value in (current_password, new_password, confirmation)
        ):
            raise ValueError
    except (UnicodeEncodeError, ValueError):
        return JSONResponse({"detail": "Invalid password change request."}, status_code=400)
    result = await db.execute(
        select(AdminCredential)
        .options(undefer(AdminCredential.password_hash))
        .where(AdminCredential.user_id == current_user.id)
        .with_for_update()
    )
    credential = result.scalar_one_or_none()
    if credential is None or not verify_password(credential.password_hash, current_password):
        return JSONResponse({"detail": "Current password was not accepted."}, status_code=422)
    if new_password != confirmation:
        return JSONResponse({"detail": "New passwords do not match."}, status_code=422)
    try:
        credential.password_hash = hash_password(new_password)
    except LocalAuthenticationError:
        return JSONResponse(
            {"detail": "New password must contain at least 15 valid characters."},
            status_code=422,
        )
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="auth.password_changed",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(current_user.id),
    )
    await db.flush()
    return JSONResponse({"changed": True})


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
