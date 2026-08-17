"""Read-only Google Workspace Directory client and additive identity sync."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, UserRole, UserSource
from app.platform_settings import PlatformSettingError, PlatformSettingsStore, SettingKey

USER_READONLY = "https://www.googleapis.com/auth/admin.directory.user.readonly"
ORGUNIT_READONLY = "https://www.googleapis.com/auth/admin.directory.orgunit.readonly"
_DIRECTORY_ROOT = "https://admin.googleapis.com/admin/directory/v1"
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class WorkspaceConfigurationError(Exception):
    """The stored Workspace configuration is missing or malformed."""


class WorkspaceAPIError(Exception):
    """A bounded, non-secret Directory API failure."""


@dataclass(frozen=True, slots=True)
class WorkspaceOrgUnit:
    path: str
    name: str


@dataclass(frozen=True, slots=True)
class WorkspaceUser:
    external_id: str
    email: str
    display_name: str
    ou_path: str
    suspended: bool


@dataclass(frozen=True, slots=True)
class SyncResult:
    seen: int
    deactivated: int


class GoogleWorkspaceClient:
    """Minimal DWD client restricted to the two read-only Directory scopes."""

    def __init__(
        self,
        service_account_json: str,
        delegated_admin: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            info = json.loads(service_account_json)
            self._client_email = str(info["client_email"])
            self._private_key = str(info["private_key"])
            self._private_key_id = str(info["private_key_id"])
            self._token_uri = str(info.get("token_uri", "https://oauth2.googleapis.com/token"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise WorkspaceConfigurationError("invalid service account JSON") from exc
        if not delegated_admin.strip() or not self._token_uri.startswith("https://"):
            raise WorkspaceConfigurationError("invalid delegated Workspace configuration")
        self._subject = delegated_admin.strip().casefold()
        self._http = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(30),
            follow_redirects=False,
            trust_env=False,
        )
        self._access_token: str | None = None
        self._expires_at = 0.0

    async def aclose(self) -> None:
        await self._http.aclose()

    async def list_org_units(self, customer: str = "my_customer") -> tuple[WorkspaceOrgUnit, ...]:
        data = await self._get_json(
            f"{_DIRECTORY_ROOT}/customer/{customer}/orgunits", {"type": "ALL"}
        )
        raw_units = data.get("organizationUnits", [])
        if not isinstance(raw_units, list):
            raise WorkspaceAPIError("invalid org-unit response")
        units: list[WorkspaceOrgUnit] = []
        for raw in raw_units:
            if isinstance(raw, dict) and isinstance(raw.get("orgUnitPath"), str):
                units.append(
                    WorkspaceOrgUnit(path=raw["orgUnitPath"], name=str(raw.get("name", "")))
                )
        return tuple(units)

    async def list_users(self, customer: str = "my_customer") -> tuple[WorkspaceUser, ...]:
        users: list[WorkspaceUser] = []
        page_token: str | None = None
        for _ in range(10_000):
            params = {
                "customer": customer,
                "maxResults": "500",
                "orderBy": "email",
                "projection": "basic",
                "viewType": "admin_view",
            }
            if page_token:
                params["pageToken"] = page_token
            data = await self._get_json(f"{_DIRECTORY_ROOT}/users", params)
            raw_users = data.get("users", [])
            if not isinstance(raw_users, list):
                raise WorkspaceAPIError("invalid users response")
            for raw in raw_users:
                parsed = _parse_user(raw)
                if parsed is not None:
                    users.append(parsed)
            next_token = data.get("nextPageToken")
            if next_token is None:
                return tuple(users)
            if not isinstance(next_token, str) or not next_token or next_token == page_token:
                raise WorkspaceAPIError("invalid users pagination")
            page_token = next_token
        raise WorkspaceAPIError("users pagination limit exceeded")

    async def _get_json(self, url: str, params: dict[str, str]) -> dict[str, Any]:
        token = await self._token()
        response = await self._http.get(
            url, params=params, headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code != 200:
            raise WorkspaceAPIError(f"Directory API returned HTTP {response.status_code}")
        if len(response.content) > _MAX_RESPONSE_BYTES:
            raise WorkspaceAPIError("Directory API response exceeded size limit")
        try:
            data = response.json()
        except ValueError as exc:
            raise WorkspaceAPIError("Directory API returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise WorkspaceAPIError("Directory API returned invalid JSON")
        return cast(dict[str, Any], data)

    async def _token(self) -> str:
        now = time.time()
        if self._access_token is not None and now < self._expires_at - 60:
            return self._access_token
        assertion = self._assertion(int(now))
        response = await self._http.post(
            self._token_uri,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
        )
        if response.status_code != 200 or len(response.content) > 64 * 1024:
            raise WorkspaceAPIError(f"OAuth token endpoint returned HTTP {response.status_code}")
        try:
            data = response.json()
            token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspaceAPIError("OAuth token endpoint returned an invalid response") from exc
        if not isinstance(token, str) or not token:
            raise WorkspaceAPIError("OAuth token endpoint returned an invalid response")
        self._access_token = token
        self._expires_at = now + max(60, min(expires_in, 3600))
        return token

    def _assertion(self, now: int) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self._private_key_id}
        claims = {
            "iss": self._client_email,
            "sub": self._subject,
            "aud": self._token_uri,
            "iat": now,
            "exp": now + 3600,
            "scope": f"{USER_READONLY} {ORGUNIT_READONLY}",
        }
        unsigned = f"{_b64_json(header)}.{_b64_json(claims)}".encode("ascii")
        try:
            key = serialization.load_pem_private_key(self._private_key.encode(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("service account key must be RSA")
            signature = key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
        except (TypeError, ValueError, AttributeError) as exc:
            raise WorkspaceConfigurationError("invalid service account private key") from exc
        return unsigned.decode("ascii") + "." + _b64(signature)


async def configured_workspace_client(
    db: AsyncSession,
    store: PlatformSettingsStore,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> GoogleWorkspaceClient:
    values = await store.read_many(
        db,
        frozenset(
            {
                SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON,
                SettingKey.GOOGLE_WORKSPACE_DELEGATED_ADMIN,
            }
        ),
    )
    service_account = values.get(SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON)
    delegated_admin = values.get(SettingKey.GOOGLE_WORKSPACE_DELEGATED_ADMIN)
    if not service_account or not delegated_admin:
        raise PlatformSettingError("Google Workspace Directory sync is not configured")
    return GoogleWorkspaceClient(service_account, delegated_admin, transport=transport)


async def sync_workspace_users(db: AsyncSession, users: tuple[WorkspaceUser, ...]) -> SyncResult:
    """Upsert Directory identities and deactivate departed sync-owned accounts; never delete."""

    active_emails: set[str] = set()
    for item in users:
        email = item.email.casefold()
        active_emails.add(email)
        statement = postgresql_insert(User).values(
            email=email,
            google_sub=item.external_id,
            display_name=item.display_name,
            ou_path=item.ou_path,
            role=UserRole.USER,
            is_active=not item.suspended,
            source=UserSource.WORKSPACE_SYNC,
        )
        await db.execute(
            statement.on_conflict_do_update(
                constraint="uq_users_email",
                set_={
                    "display_name": statement.excluded.display_name,
                    "ou_path": statement.excluded.ou_path,
                    "is_active": statement.excluded.is_active,
                    "google_sub": statement.excluded.google_sub,
                },
            )
        )
    departed = update(User).where(
        User.source == UserSource.WORKSPACE_SYNC, User.is_active.is_(True)
    )
    if active_emails:
        departed = departed.where(User.email.not_in(active_emails))
    result = await db.execute(departed.values(is_active=False))
    await db.flush()
    rowcount = cast(int | None, getattr(result, "rowcount", 0))
    return SyncResult(seen=len(users), deactivated=max(0, rowcount or 0))


def _parse_user(raw: object) -> WorkspaceUser | None:
    if not isinstance(raw, dict):
        return None
    external_id, email = raw.get("id"), raw.get("primaryEmail")
    if not isinstance(external_id, str) or not isinstance(email, str):
        return None
    name = raw.get("name")
    display = name.get("fullName") if isinstance(name, dict) else None
    return WorkspaceUser(
        external_id=external_id,
        email=email.casefold(),
        display_name=display if isinstance(display, str) and display else email,
        ou_path=str(raw.get("orgUnitPath", "/")),
        suspended=raw.get("suspended") is True,
    )


def _b64_json(value: Mapping[str, object]) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
