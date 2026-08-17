"""Super-admin user and encrypted integration configuration screens."""

from __future__ import annotations

import html
import json
import re
import uuid
from typing import Annotated, cast
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth.authorization import require_role
from app.auth.local import normalise_admin_email, normalise_display_name
from app.db import get_db_session
from app.models import User, UserRole, UserSource
from app.platform_settings import SECRET_KEYS, PlatformSettingsStore, SettingKey

_ADMIN_GUARD = require_role(UserRole.SUPER_ADMIN)
_MAX_BODY_BYTES = 32 * 1024
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
    soc_email: str | None = Field(default=None, max_length=320)

    @field_validator("google_redirect_uri", "wazuh_url", "dfir_iris_url")
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
    role: UserRole = UserRole.USER

    @field_validator("role")
    @classmethod
    def no_web_superadmins(cls, value: UserRole) -> UserRole:
        if value is UserRole.SUPER_ADMIN:
            raise ValueError("super-admin accounts must be provisioned with create-superadmin")
        return value


def get_platform_store(request: Request) -> PlatformSettingsStore:
    return cast(PlatformSettingsStore, request.app.state.platform_settings)


@router.get("/settings", response_model=None)
async def settings_page(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    store: PlatformSettingsStore = Depends(get_platform_store),  # noqa: B008
) -> HTMLResponse:
    """Render a blank-safe configuration page that never returns stored secret values."""

    configured = await store.configured_state(db)
    rows = "".join(
        "<tr><td>"
        + html.escape(key.value)
        + "</td><td>"
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
    body = "".join(
        (
            '<!doctype html><html><head><meta charset="utf-8">',
            "<title>LeakCheck settings</title>",
            '<link rel="stylesheet" href="/static/admin-settings.css">',
            "</head><body><main>",
            "<h1>Platform settings</h1>",
            "<p>Secrets are encrypted at rest and are never displayed.</p>",
            '<form id="settings-form"><h2>Google sign-in</h2>',
            oidc_fields,
            '<h2>Google Workspace OU sync <button type="button" class="help-button" ',
            'aria-label="How to configure Google Workspace OU sync" ',
            'data-dialog-open="google-workspace-help">?</button></h2>',
            "<p>Read-only Directory access using domain-wide delegation.</p>",
            workspace_fields,
            "<h2>Other integrations</h2>",
            other_fields,
            '<button type="submit">Save settings</button></form>',
            _workspace_help_dialog(),
            "<h2>Configuration status</h2><table><thead><tr>",
            f"<th>Setting</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>",
            '<h2>Add user</h2><form id="user-form">',
            '<label>Email <input name="email" required></label>',
            '<label>Name <input name="display_name" required></label>',
            '<label>Role <select name="role"><option value="user">User</option>',
            '<option value="analyst">Analyst</option></select></label>',
            '<button type="submit">Add user</button></form>',
            '<output id="result"></output></main>',
            '<script src="/static/admin-settings.js" defer></script></body></html>',
        )
    )
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


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
        # Never reflect a submitted API key, private key, or password through validation details.
        raise HTTPException(status_code=422, detail="One or more settings are invalid.") from exc
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
    return JSONResponse({"updated": sorted(key.value for key in values)})


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


async def _json_body(request: Request) -> object:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Request body is too large.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length.") from exc
    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
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
    if key is SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON:
        return (
            f'<label>{label}<br><textarea name="{escaped_key}" rows="8" cols="72" '
            f'placeholder="{html.escape(placeholder)}" autocomplete="off"></textarea></label><br>'
        )
    return (
        f'<label>{label} <input type="{input_type}" name="{escaped_key}" '
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
