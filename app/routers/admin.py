"""Super-admin user and encrypted integration configuration screens."""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
import uuid
from typing import Annotated, Self, cast
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import branding
from app.alerts import enqueue_test_alert
from app.audit import audit_event
from app.auth.authorization import require_role
from app.auth.local import normalise_admin_email, normalise_display_name
from app.auth.session import SessionManager
from app.db import get_db_session
from app.google_workspace import (
    WorkspaceAPIError,
    WorkspaceConfigurationError,
    configured_workspace_client,
    sync_workspace_users,
)
from app.layout import page
from app.models import AlertSinkName, Scan, Session, User, UserRole, UserSource
from app.platform_settings import (
    SECRET_KEYS,
    PlatformSettingError,
    PlatformSettingsStore,
    SettingKey,
)
from app.retention import load_policy

_ADMIN_GUARD = require_role(UserRole.SUPER_ADMIN)
_MAX_BODY_BYTES = 32 * 1024
_MAX_LOGO_BODY_BYTES = 2 * 1024 * 1024
_DOMAIN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_GOOGLE_OIDC_KEYS = (
    SettingKey.GOOGLE_CLIENT_ID,
    SettingKey.GOOGLE_CLIENT_SECRET,
    SettingKey.GOOGLE_REDIRECT_URI,
    SettingKey.GOOGLE_WORKSPACE_DOMAINS,
)
_GOOGLE_WORKSPACE_KEYS = (
    SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON,
    SettingKey.GOOGLE_WORKSPACE_DELEGATED_ADMIN,
)
_SETTING_LABELS = {
    SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON: "Service-account JSON",
    SettingKey.GOOGLE_WORKSPACE_DELEGATED_ADMIN: "Delegated Workspace admin email",
    SettingKey.GOOGLE_WORKSPACE_DOMAINS: "Allowed Workspace domains (comma-separated)",
    SettingKey.SMTP_SECURITY: "SMTP transport security",
    SettingKey.PUBLIC_BASE_URL: "Public portal base URL (HTTPS)",
    SettingKey.NOTIFY_DRY_RUN: "Notification dry-run",
    SettingKey.NOTIFY_COOLDOWN_SECONDS: "Per-user notification cooldown (seconds)",
}

router = APIRouter(prefix="/admin", dependencies=[Depends(_ADMIN_GUARD)], include_in_schema=False)


class SettingsUpdate(BaseModel):
    """Allowed operational settings. Omitted values are left unchanged."""

    leakcheck_api_key: str | None = Field(default=None, max_length=1024)
    leakcheck_rps: Annotated[int | None, Field(default=None, ge=1, le=20)]
    leakcheck_concurrency: Annotated[int | None, Field(default=None, ge=1, le=50)]
    leakcheck_max_response_bytes: Annotated[
        int | None, Field(default=None, ge=1024, le=128 * 1024 * 1024)
    ]
    self_check_cooldown_seconds: Annotated[
        int | None, Field(default=None, ge=60, le=30 * 24 * 60 * 60)
    ]
    google_client_id: str | None = Field(default=None, max_length=512)
    google_client_secret: str | None = Field(default=None, max_length=2048)
    google_redirect_uri: str | None = Field(default=None, max_length=2048)
    google_workspace_domains: list[str] | None = Field(default=None, max_length=100)
    google_workspace_service_account_json: str | None = Field(default=None, max_length=16 * 1024)
    google_workspace_delegated_admin: str | None = Field(default=None, max_length=320)
    wazuh_url: str | None = Field(default=None, max_length=2048)
    wazuh_username: str | None = Field(default=None, max_length=512)
    wazuh_password: str | None = Field(default=None, max_length=2048)
    dfir_iris_url: str | None = Field(default=None, max_length=2048)
    dfir_iris_api_key: str | None = Field(default=None, max_length=2048)
    dfir_iris_customer_id: str | None = Field(default=None, max_length=255)
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: Annotated[int | None, Field(default=None, ge=1, le=65535)]
    smtp_username: str | None = Field(default=None, max_length=512)
    smtp_password: str | None = Field(default=None, max_length=2048)
    smtp_from: str | None = Field(default=None, max_length=320)
    smtp_security: str | None = Field(default=None, pattern="^(starttls|tls)$")
    public_base_url: str | None = Field(default=None, max_length=2048)
    notify_dry_run: bool | None = None
    notify_cooldown_seconds: Annotated[int | None, Field(default=None, ge=0, le=30 * 24 * 60 * 60)]
    soc_email: str | None = Field(default=None, max_length=320)
    retention_mode: str | None = Field(default=None, pattern="^(indefinite|none|days)$")
    retention_days: Annotated[int | None, Field(default=None, ge=1, le=3650)]

    @model_validator(mode="after")
    def retention_days_required_for_a_day_based_policy(self) -> Self:
        if self.retention_mode == "days" and self.retention_days is None:
            raise ValueError("retention_days is required when retention_mode is 'days'")
        return self

    @field_validator("google_redirect_uri", "wazuh_url", "dfir_iris_url", "public_base_url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("must be an HTTP(S) URL without embedded credentials or a fragment")
        return value.rstrip("/")

    @field_validator("google_redirect_uri")
    @classmethod
    def validate_google_redirect(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        parsed = urlsplit(value)
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        if (
            (parsed.scheme != "https" and not local_http)
            or parsed.path != "/auth/google/callback"
            or parsed.query
        ):
            raise ValueError("must be HTTPS (or local HTTP) and end in /auth/google/callback")
        return value

    @field_validator("google_workspace_domains")
    @classmethod
    def validate_domains(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalised: list[str] = []
        for item in value:
            domain = item.strip().casefold().rstrip(".").encode("idna").decode("ascii")
            if _DOMAIN.fullmatch(domain) is None:
                raise ValueError("contains an invalid domain")
            normalised.append(domain)
        if not normalised:
            raise ValueError("must contain at least one domain")
        return list(dict.fromkeys(normalised))

    @field_validator("google_workspace_service_account_json")
    @classmethod
    def validate_service_account_json(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        try:
            credential = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("must be a valid service-account JSON document") from exc
        required_string_fields = {
            "project_id",
            "private_key_id",
            "private_key",
            "client_email",
            "client_id",
            "token_uri",
        }
        if (
            not isinstance(credential, dict)
            or credential.get("type") != "service_account"
            or any(
                not isinstance(credential.get(field), str) or not credential[field]
                for field in required_string_fields
            )
            or credential.get("token_uri") != "https://oauth2.googleapis.com/token"
            or not str(credential.get("private_key", "")).startswith(
                "-----BEGIN PRIVATE KEY-----\n"
            )
        ):
            raise ValueError("must be an unmodified Google service-account key JSON document")
        return json.dumps(credential, separators=(",", ":"), sort_keys=True)

    @field_validator("google_workspace_delegated_admin")
    @classmethod
    def validate_delegated_admin(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        return normalise_admin_email(value)


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    # A super-admin may grant the role from this screen. The account still has no local password
    # or TOTP: it authenticates through Google. Provision local credentials with
    # `python -m app.create_superadmin` when a break-glass login is wanted as well.
    role: UserRole = UserRole.USER


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None


def _role_options(selected: UserRole) -> str:
    labels = {
        UserRole.USER: "User",
        UserRole.ANALYST: "Analyst",
        UserRole.SUPER_ADMIN: "Super admin",
    }
    return "".join(
        f'<option value="{role.value}"{" selected" if role is selected else ""}>'
        f"{labels[role]}</option>"
        for role in UserRole
    )


def _logo_preview(brand: branding.OrganisationBranding) -> str:
    if not brand.has_logo:
        return '<p id="logo-preview">No logo uploaded.</p>'
    # The digest busts the cache when the logo is replaced.
    digest = html.escape(brand.logo_sha256 or "")
    return (
        '<p id="logo-preview"><img class="logo-preview" alt="Current organisation logo" '
        f'src="/branding/logo?v={digest}"></p>'
    )


def _retention_options(selected: str) -> str:
    labels = {
        "indefinite": "Keep indefinitely",
        "none": "Delete on remediation",
        "days": "Delete after N days",
    }
    return "".join(
        f'<option value="{value}"{" selected" if value == selected else ""}>{label}</option>'
        for value, label in labels.items()
    )


def _quota_panel(row: object) -> str:
    """Show the most recent vendor quota observation, which lags one request by design."""

    if row is None:
        return "<p>No quota has been observed yet. Run a scan to record one.</p>"
    quota, observed_at = cast(tuple[int, object], row)
    return (
        "<p><strong>"
        + html.escape(f"{quota:,}")
        + "</strong> units remaining, observed "
        + html.escape(str(observed_at))
        + ".</p>"
        + "<p>The vendor reports quota one request behind, and queries returning no results "
        + "cost nothing, so treat this as approximate.</p>"
    )


def _user_rows(users: list[User], *, current_user: User, sessions: dict[uuid.UUID, int]) -> str:
    if not users:
        return '<tr><td colspan="6">No users yet.</td></tr>'
    rows = []
    for user in users:
        is_self = user.id == current_user.id
        self_note = ' <span class="badge">you</span>' if is_self else ""
        # A super-admin must not strip their own access; the server rejects it either way.
        lock = " disabled" if is_self else ""
        rows.append(
            '<tr data-user-id="'
            + html.escape(str(user.id))
            + '">'
            + "<td>"
            + html.escape(user.email)
            + self_note
            + "</td>"
            + '<td><input name="display_name" value="'
            + html.escape(user.display_name)
            + '"></td>'
            + '<td><select name="role"'
            + lock
            + ">"
            + _role_options(user.role)
            + "</select></td>"
            + '<td><input type="checkbox" name="is_active"'
            + (" checked" if user.is_active else "")
            + lock
            + "></td>"
            + "<td>"
            + str(sessions.get(user.id, 0))
            + "</td>"
            + '<td><button type="button" data-save-user>Save</button> '
            + '<button type="button" data-revoke-sessions>Sign out</button></td></tr>'
        )
    return "".join(rows)


def get_platform_store(request: Request) -> PlatformSettingsStore:
    return cast(PlatformSettingsStore, request.app.state.platform_settings)


@router.get("/settings", response_model=None)
async def settings_page(
    request: Request,
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    store: PlatformSettingsStore = Depends(get_platform_store),  # noqa: B008
) -> HTMLResponse:
    """Render a blank-safe configuration page that never returns stored secret values."""

    configured = await store.configured_state(db)
    listed = await db.execute(select(User).order_by(User.email))
    users = list(listed.scalars().all())
    retention = await load_policy(db, store)
    brand = await branding.load(db)
    quota_row = await db.execute(
        select(Scan.quota, Scan.started_at)
        .where(Scan.quota.is_not(None))
        .order_by(Scan.started_at.desc())
        .limit(1)
    )
    latest_quota = quota_row.first()
    session_rows = await db.execute(
        select(Session.user_id, func.count())
        .where(Session.revoked_at.is_(None), Session.expires_at > func.now())
        .group_by(Session.user_id)
    )
    active_sessions = {user_id: count for user_id, count in session_rows.all()}
    rows = "".join(
        "<tr><td>"
        + html.escape(key.value)
        + '</td><td data-setting-status="'
        + html.escape(key.value)
        + '">'
        + ("configured" if configured[key.value] else "blank")
        + "</td></tr>"
        for key in SettingKey
    )
    oidc_fields = "".join(
        _setting_input(key, configured=bool(configured[key.value])) for key in _GOOGLE_OIDC_KEYS
    )
    workspace_fields = "".join(
        _setting_input(key, configured=bool(configured[key.value]))
        for key in _GOOGLE_WORKSPACE_KEYS
    )
    other_fields = "".join(
        _setting_input(key, configured=bool(configured[key.value]))
        for key in SettingKey
        if key not in _GOOGLE_OIDC_KEYS and key not in _GOOGLE_WORKSPACE_KEYS
    )
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Administration</p>',
            "<h1>Settings</h1><p>Configure platform integrations and user access. ",
            "Secrets are encrypted at rest and are never displayed.</p></section>",
            '<form id="settings-form" class="settings-stack"><section class="panel">',
            "<h2>Google sign-in</h2>",
            oidc_fields,
            '<p class="panel-actions"><button type="submit">Save</button>'
            "<small>Saves every settings panel; blank fields are "
            "left unchanged.</small></p>",
            '</section><section class="panel"><h2>Google Workspace OU sync ',
            '<button type="button" class="help-button" ',
            'aria-label="How to configure Google Workspace OU sync" ',
            'data-dialog-open="google-workspace-help">?</button></h2>',
            "<p>Read-only Directory access using domain-wide delegation.</p>",
            workspace_fields,
            '<p class="panel-actions"><button type="submit">Save</button>'
            "<small>Saves every settings panel; blank fields are "
            "left unchanged.</small></p>",
            '<p><button type="button" id="workspace-sync">Sync Workspace users now</button></p>',
            '</section><section class="panel"><h2>Other integrations</h2>',
            other_fields,
            '<p class="panel-actions"><button type="submit">Save</button>'
            "<small>Saves every settings panel; blank fields are "
            "left unchanged.</small></p>",
            "</section></form>",
            '<section class="panel"><h2>SIEM test alerts</h2>',
            "<p>These queue a contract-neutral test event. Delivery remains inactive until ",
            "the corresponding live API contract has been verified.</p>",
            '<button type="button" data-test-alert="wazuh">Queue Wazuh test</button>',
            '<button type="button" data-test-alert="dfir_iris">Queue DFIR-IRIS test</button>',
            "</section>",
            _workspace_help_dialog(),
            '<section class="panel"><h2>Data retention</h2>',
            "<p>",
            html.escape(retention.describe()),
            "</p>",
            '<label>Policy <select name="retention_mode" form="settings-form">',
            _retention_options(retention.mode),
            "</select></label>",
            '<label>Days <input type="number" name="retention_days" min="1" max="3650" ',
            'form="settings-form" value="',
            html.escape(str(retention.days) if retention.days else ""),
            '"></label>',
            "<p>Only remediated findings are deleted; an open exposure is never removed ",
            "automatically. Deletion is permanent and is not written to the event trail.</p>",
            '<p class="panel-actions"><button type="submit" form="settings-form">Save</button></p>',
            "</section>",
            '<section class="panel"><h2>Organisation branding</h2>',
            "<p>Shown on the sign-in page. PNG, JPEG, GIF, or WebP up to 1 MB; SVG is not ",
            "accepted because it can carry script.</p>",
            '<form id="branding-form">',
            '<label>Organisation name <input name="organization_name" maxlength="120" value="',
            html.escape(brand.name or ""),
            '"></label>',
            '<label>Logo <input type="file" id="logo-file" accept="image/png,image/jpeg,'
            'image/gif,image/webp"></label>',
            _logo_preview(brand),
            '<p class="panel-actions"><button type="submit">Save branding</button>',
            '<button type="button" id="clear-logo">Remove logo</button></p>',
            "</form></section>",
            '<section class="panel"><h2>LeakCheck quota</h2>',
            _quota_panel(latest_quota),
            "</section>",
            '<section class="panel"><h2>Configuration status</h2><div class="table-wrap">',
            "<table><thead><tr>",
            f"<th>Setting</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>",
            '</section><section class="panel"><h2>Users</h2>',
            "<p>Change a name, role, or access, then save the row. Granting super-admin here does ",
            "not create a local password or TOTP; that account signs in through Google. Use ",
            "<code>python -m app.create_superadmin</code> to add break-glass local ",
            "credentials.</p>",
            '<div class="table-wrap"><table><thead><tr><th>Email</th><th>Name</th>',
            "<th>Role</th><th>Active</th><th>Sessions</th><th></th>",
            "</tr></thead><tbody>",
            _user_rows(users, current_user=current_user, sessions=active_sessions),
            "</tbody></table></div></section>",
            '<section class="panel"><h2>Add user</h2><form id="user-form">',
            '<label>Email <input name="email" required></label>',
            '<label>Name <input name="display_name" required></label>',
            '<label>Role <select name="role"><option value="user">User</option>',
            '<option value="analyst">Analyst</option>',
            '<option value="super_admin">Super admin</option></select></label>',
            '<button type="submit">Add user</button></form>',
            '<output id="result"></output></section>',
        )
    )
    body = page(
        "Settings",
        content,
        user=current_user,
        extra_styles=("/static/admin-settings.css?v=7",),
        extra_scripts=("/static/admin-settings.js?v=7",),
    )
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


def _validation_detail(error: ValidationError) -> str:
    """Say which setting was rejected and why, without echoing what was submitted.

    Only the field name and the validator's own static message are used. Pydantic also carries the
    offending input, which must never be reflected: these fields include API keys, a service-account
    private key, and SMTP and SIEM passwords.
    """

    problems: list[str] = []
    for item in error.errors():
        field = str(item["loc"][0]) if item.get("loc") else "request"
        label = _SETTING_LABELS.get(SettingKey(field), field) if _is_setting(field) else field
        message = str(item.get("msg", "is invalid")).removeprefix("Value error, ")
        if _is_setting(field) and SettingKey(field) in SECRET_KEYS:
            # Naming the constraint on a secret field would describe the value itself.
            problems.append(f"{label} was rejected")
        else:
            problems.append(f"{label}: {message}")
    unique = list(dict.fromkeys(problems))
    return "; ".join(unique[:4]) or "One or more settings are invalid."


def _is_setting(field: str) -> bool:
    try:
        SettingKey(field)
    except ValueError:
        return False
    return True


@router.post("/settings", response_model=None)
async def update_settings(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    store: PlatformSettingsStore = Depends(get_platform_store),  # noqa: B008
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
) -> JSONResponse:
    """Validate and encrypt operational configuration supplied from the settings page."""

    try:
        payload = SettingsUpdate.model_validate(await _json_body(request))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_validation_detail(exc)) from exc
    raw = payload.model_dump(exclude_unset=True)
    values: dict[SettingKey, str | None] = {}
    for name, value in raw.items():
        key = SettingKey(name)
        if key is SettingKey.GOOGLE_WORKSPACE_DOMAINS and isinstance(value, list):
            values[key] = store.encode_domains(value)
        elif value is None or isinstance(value, str):
            values[key] = value
        else:
            values[key] = str(value)
    await store.write_many(db, values, actor_id=current_user.id)
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.settings_updated",
        actor_id=current_user.id,
        target_type="platform_settings",
        meta={"keys": sorted(key.value for key in values)},
    )
    # The page renders configured/blank state server-side, so hand back the post-write state and
    # let the browser update in place rather than making the operator reload to see the effect.
    return JSONResponse(
        {
            "updated": sorted(key.value for key in values),
            "configured": await store.configured_state(db),
        }
    )


@router.post("/users", response_model=None)
async def create_user(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
) -> JSONResponse:
    """Pre-provision a Google-login user or analyst without creating local credentials."""

    payload = UserCreate.model_validate(await _json_body(request))
    email = normalise_admin_email(payload.email)
    name = normalise_display_name(payload.display_name)
    existing = await db.execute(select(User).where(User.email == email).with_for_update())
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A user with this email already exists.")
    user = User(
        id=uuid.uuid4(),
        email=email,
        display_name=name,
        role=payload.role,
        source=UserSource.MANUAL,
    )
    db.add(user)
    await db.flush()
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.user_created",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(user.id),
        meta={"role": user.role.value},
    )
    return JSONResponse(
        {"id": str(user.id), "email": user.email, "role": user.role.value}, status_code=201
    )


async def _remaining_super_admins(db: AsyncSession, *, excluding: uuid.UUID) -> int:
    """Count the active super-admins that would survive a change to ``excluding``."""

    rows = await db.execute(
        select(User.id).where(
            User.role == UserRole.SUPER_ADMIN,
            User.is_active.is_(True),
            User.id != excluding,
        )
    )
    return len(rows.scalars().all())


@router.post("/users/{user_id}", response_model=None)
async def update_user(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
) -> JSONResponse:
    """Change an existing user's name, role, or active state, including granting super-admin."""

    payload = UserUpdate.model_validate(await _json_body(request))
    found = await db.execute(select(User).where(User.id == user_id).with_for_update())
    user = found.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="No such user.")

    before = {"display_name": user.display_name, "role": user.role.value, "active": user.is_active}
    demoted = payload.role is not None and payload.role is not UserRole.SUPER_ADMIN
    deactivated = payload.is_active is False
    if user.id == current_user.id and (demoted or deactivated):
        # Removing your own access mid-session is the fastest route to an unadministrable portal.
        raise HTTPException(
            status_code=409,
            detail="You cannot remove your own super-admin access. Ask another super-admin.",
        )
    if user.role is UserRole.SUPER_ADMIN and (demoted or deactivated):
        if await _remaining_super_admins(db, excluding=user.id) == 0:
            raise HTTPException(
                status_code=409,
                detail="This is the last active super-admin. Grant the role to someone else first.",
            )

    if payload.display_name is not None:
        user.display_name = normalise_display_name(payload.display_name)
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    await db.flush()
    after = {"display_name": user.display_name, "role": user.role.value, "active": user.is_active}
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.user_updated",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(user.id),
        meta={"before": before, "after": after},
    )
    return JSONResponse({"id": str(user.id), "role": user.role.value, "is_active": user.is_active})


class BrandingUpdate(BaseModel):
    organization_name: str | None = Field(default=None, max_length=120)
    # Base64 rather than multipart: FastAPI file uploads need python-multipart, and a new runtime
    # dependency is not worth one form.
    logo_base64: str | None = Field(default=None, max_length=2 * 1024 * 1024)
    clear_logo: bool = False


@router.post("/branding", response_model=None)
async def update_branding(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
) -> JSONResponse:
    """Set the organisation name and logo shown on the sign-in page."""

    payload = BrandingUpdate.model_validate(await _json_body(request, limit=_MAX_LOGO_BODY_BYTES))
    changed: list[str] = []
    if payload.organization_name is not None:
        await branding.set_name(db, payload.organization_name)
        changed.append("organization_name")
    if payload.clear_logo:
        await branding.clear_logo(db)
        changed.append("logo_cleared")
    elif payload.logo_base64:
        try:
            raw = base64.b64decode(payload.logo_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=422, detail="The logo is not valid base64.") from exc
        try:
            await branding.set_logo(db, raw)
        except branding.LogoRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        changed.append("logo")
    if not changed:
        raise HTTPException(status_code=422, detail="Nothing to update.")
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.branding_updated",
        actor_id=current_user.id,
        target_type="branding",
        meta={"changed": changed},
    )
    current = await branding.load(db)
    return JSONResponse(
        {
            "changed": changed,
            "organization_name": current.name,
            "has_logo": current.has_logo,
            "logo_sha256": current.logo_sha256,
        }
    )


@router.post("/users/{user_id}/sessions/revoke", response_model=None)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
) -> JSONResponse:
    """Sign an account out of every browser, for offboarding or a suspected compromise."""

    found = await db.execute(select(User).where(User.id == user_id))
    user = found.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="No such user.")
    manager = cast(SessionManager, request.app.state.session_manager)
    revoked = await manager.revoke_all(db, user_id=user.id)
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.sessions_revoked",
        actor_id=current_user.id,
        target_type="user",
        target_id=str(user.id),
        meta={"revoked": revoked},
    )
    return JSONResponse({"revoked": revoked})


@router.post("/workspace/sync", response_model=None)
async def sync_workspace(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    store: PlatformSettingsStore = Depends(get_platform_store),  # noqa: B008
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
) -> JSONResponse:
    """Run a complete additive Directory sync; only sync-owned departed users are disabled."""

    client = None
    try:
        client = await configured_workspace_client(db, store)
        users = await client.list_users()
    except (PlatformSettingError, WorkspaceAPIError, WorkspaceConfigurationError) as exc:
        await audit_event(
            db,
            request,
            request.app.state.settings,
            action="admin.workspace_sync_failed",
            actor_id=current_user.id,
            target_type="workspace",
            meta={"reason": type(exc).__name__},
        )
        raise HTTPException(status_code=502, detail="Workspace sync failed.") from exc
    finally:
        if client is not None:
            await client.aclose()
    result = await sync_workspace_users(db, users)
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.workspace_synced",
        actor_id=current_user.id,
        target_type="workspace",
        meta={"seen": result.seen, "deactivated": result.deactivated},
    )
    return JSONResponse({"seen": result.seen, "deactivated": result.deactivated})


@router.post("/alerts/test/{sink}", response_model=None)
async def queue_test_alert(
    sink: AlertSinkName,
    request: Request,
    current_user: User = Depends(_ADMIN_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> JSONResponse:
    """Queue a safe internal test envelope without assuming a remote contract."""

    await enqueue_test_alert(db, sink)
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="admin.test_alert_queued",
        actor_id=current_user.id,
        target_type="alert_sink",
        target_id=sink.value,
    )
    return JSONResponse({"queued": sink.value}, status_code=202)


async def _json_body(request: Request, *, limit: int = _MAX_BODY_BYTES) -> object:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > limit:
                raise HTTPException(status_code=413, detail="Request body is too large.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length.") from exc
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(status_code=413, detail="Request body is too large.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Expected a JSON object.") from exc


def _setting_input(key: SettingKey, *, configured: bool) -> str:
    secret = key in SECRET_KEYS
    input_type = "password" if secret else "text"
    placeholder = "configured — leave blank to keep" if secret and configured else ""
    escaped_key = html.escape(key.value)
    label = html.escape(_SETTING_LABELS.get(key, key.value.replace("_", " ").title()))
    if key is SettingKey.NOTIFY_DRY_RUN:
        return (
            f'<label>{label} <select name="{escaped_key}">'
            '<option value="true" selected>Enabled (safe default)</option>'
            '<option value="false">Disabled — send mail</option></select></label><br>'
        )
    if key is SettingKey.SMTP_SECURITY:
        return (
            f'<label>{label} <select name="{escaped_key}">'
            '<option value="starttls">STARTTLS</option>'
            '<option value="tls">Implicit TLS</option></select></label><br>'
        )
    if key is SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON:
        return (
            f'<label>{label}<br><textarea name="{escaped_key}" rows="8" cols="72" '
            f'data-setting-input="{escaped_key}" '
            f'placeholder="{html.escape(placeholder)}" autocomplete="off"></textarea></label><br>'
        )
    return (
        f'<label>{label} <input type="{input_type}" name="{escaped_key}" '
        f'data-setting-input="{escaped_key}" '
        f'placeholder="{html.escape(placeholder)}" autocomplete="off"></label><br>'
    )


def _workspace_help_dialog() -> str:
    """Return secret-free setup guidance for Google Directory OU synchronization."""

    return "".join(
        (
            '<dialog id="google-workspace-help" aria-labelledby="workspace-help-title">',
            '<h2 id="workspace-help-title">Set up Google Workspace OU access</h2>',
            "<ol>",
            "<li>In Google Cloud Console, select or create the project used by LeakCheck.</li>",
            "<li>Open APIs &amp; Services, then enable the <strong>Admin SDK API</strong>.</li>",
            "<li>Open IAM &amp; Admin → Service Accounts and create a dedicated service ",
            "account.</li>",
            "<li>Open that account, enable domain-wide delegation, and copy its numeric OAuth ",
            "client ID.</li>",
            "<li>Open Keys → Add key → Create new key → JSON. Download it once and keep it ",
            "private.</li>",
            "<li>In the Google Admin console, open Security → Access and data control → API ",
            "controls → Manage Domain Wide Delegation, then add the service account client ",
            "ID.</li>",
            "<li>Authorize exactly these comma-separated scopes:<br><code>",
            "https://www.googleapis.com/auth/admin.directory.user.readonly,",
            "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
            "</code></li>",
            "<li>Enter a dedicated Workspace admin account that the service account will ",
            "impersonate. It needs permission to read users and organizational units.</li>",
            "<li>Paste the <strong>entire downloaded JSON document</strong> into Service-account ",
            "JSON—not only the private_key value. LeakCheck validates it, encrypts it, and never ",
            "displays it again.</li>",
            "</ol>",
            '<p>The expected file starts with <code>{"type":"service_account",',
            '"project_id":"…","private_key_id":"…","private_key":"…",',
            '"client_email":"…","client_id":"…"}</code>. Do not paste a real key ',
            "into chat, tickets, or documentation.</p>",
            '<form method="dialog"><button type="submit">Close</button></form></dialog>',
        )
    )
