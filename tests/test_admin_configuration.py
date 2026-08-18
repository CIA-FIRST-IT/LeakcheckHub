"""Validation tests for the super-admin settings and user screens."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, UserRole, UserSource
from app.routers.admin import (
    SettingsUpdate,
    UserCreate,
    _user_rows,
    _workspace_help_dialog,
    update_user,
)


def service_account_json() -> str:
    return json.dumps(
        {
            "type": "service_account",
            "project_id": "leakcheck-fixture",
            "private_key_id": "fixture-key-id",
            "private_key": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n",
            "client_email": "leakcheck@leakcheck-fixture.iam.gserviceaccount.com",
            "client_id": "123456789012345678901",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


def test_settings_accept_complete_blank_slate_integration_configuration() -> None:
    update = SettingsUpdate(
        leakcheck_api_key="enterprise-key-fixture",
        leakcheck_rps=3,
        self_check_cooldown_seconds=3600,
        google_client_id="client.apps.googleusercontent.com",
        google_client_secret="client-secret-fixture",  # noqa: S106 - synthetic setting
        google_redirect_uri="https://portal.example.test/auth/google/callback",
        google_workspace_domains=["Example.Test", "example.test"],
        google_workspace_service_account_json=service_account_json(),
        google_workspace_delegated_admin="Directory.Admin@Example.Test",
        wazuh_url="https://wazuh.internal.example.test",
        dfir_iris_url="https://iris.internal.example.test",
    )

    assert update.google_workspace_domains == ["example.test"]
    assert update.google_workspace_delegated_admin == "directory.admin@example.test"
    assert update.google_workspace_service_account_json is not None
    assert json.loads(update.google_workspace_service_account_json)["type"] == "service_account"
    assert update.leakcheck_rps == 3
    assert update.self_check_cooldown_seconds == 3600


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://portal.example.test/auth/google/callback",
        "https://portal.example.test/wrong-path",
        "https://user:password@portal.example.test/auth/google/callback",
    ],
)
def test_google_redirect_rejects_unsafe_values(redirect_uri: str) -> None:
    with pytest.raises(ValidationError):
        SettingsUpdate(google_redirect_uri=redirect_uri)


@pytest.mark.parametrize(
    "credential",
    [
        "not-json",
        "{}",
        json.dumps({"type": "authorized_user"}),
    ],
)
def test_workspace_credential_requires_a_service_account_key_document(credential: str) -> None:
    with pytest.raises(ValidationError, match="service-account"):
        SettingsUpdate(google_workspace_service_account_json=credential)


def test_workspace_question_mark_help_contains_exact_read_only_setup() -> None:
    dialog = _workspace_help_dialog()

    assert "Admin SDK API" in dialog
    assert "Manage Domain Wide Delegation" in dialog
    assert "admin.directory.user.readonly" in dialog
    assert "admin.directory.orgunit.readonly" in dialog
    assert "entire downloaded JSON document" in dialog
    assert "Do not paste a real key" in dialog
    assert "BEGIN PRIVATE KEY" not in dialog


class _Result:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalar_one_or_none(self) -> object | None:
        return self._rows[0] if self._rows else None

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[object]:
        return self._rows


class _UserSession:
    """Minimal session returning the target user first, then the surviving super-admins."""

    def __init__(self, target: User, others: list[User]) -> None:
        self._results = [_Result([target]), _Result([u.id for u in others])]
        self.added: list[object] = []

    async def execute(self, *_: object, **__: object) -> _Result:
        return self._results.pop(0)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None


def _user(role: UserRole, *, active: bool = True, email: str = "person@example.test") -> User:
    return User(
        id=uuid.uuid4(),
        email=email,
        display_name="Person",
        role=role,
        is_active=active,
        source=UserSource.MANUAL,
    )


async def _update(target: User, actor: User, others: list[User], body: dict[str, object]) -> object:
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=None)))
    with (
        patch("app.routers.admin._json_body", AsyncMock(return_value=body)),
        patch("app.routers.admin.audit_event", AsyncMock()),
    ):
        return await update_user(
            target.id,
            cast(Request, request),
            db=cast(AsyncSession, _UserSession(target, others)),
            current_user=actor,
        )


def test_web_user_creation_may_now_grant_super_admin() -> None:
    """A super-admin can provision another super-admin without the CLI."""

    created = UserCreate(
        email="admin@example.test", display_name="Admin", role=UserRole.SUPER_ADMIN
    )
    assert created.role is UserRole.SUPER_ADMIN


@pytest.mark.anyio
async def test_super_admin_can_promote_another_user() -> None:
    target = _user(UserRole.ANALYST)
    actor = _user(UserRole.SUPER_ADMIN, email="root@example.test")

    await _update(target, actor, [actor], {"role": "super_admin"})

    assert target.role is UserRole.SUPER_ADMIN


@pytest.mark.anyio
async def test_a_super_admin_cannot_remove_their_own_access() -> None:
    """Self-demotion is the fastest route to a portal nobody can administer."""

    actor = _user(UserRole.SUPER_ADMIN)
    other = _user(UserRole.SUPER_ADMIN, email="second@example.test")

    with pytest.raises(HTTPException) as demote:
        await _update(actor, actor, [other], {"role": "analyst"})
    assert demote.value.status_code == 409

    with pytest.raises(HTTPException) as disable:
        await _update(actor, actor, [other], {"is_active": False})
    assert disable.value.status_code == 409


@pytest.mark.anyio
async def test_the_last_super_admin_cannot_be_demoted() -> None:
    target = _user(UserRole.SUPER_ADMIN)
    actor = _user(UserRole.SUPER_ADMIN, email="root@example.test")

    with pytest.raises(HTTPException) as exc:
        await _update(target, actor, [], {"role": "user"})

    assert exc.value.status_code == 409
    assert target.role is UserRole.SUPER_ADMIN


def test_user_rows_lock_the_current_user_and_escape_breach_of_markup() -> None:
    actor = _user(UserRole.SUPER_ADMIN, email="root@example.test")
    other = _user(UserRole.ANALYST, email="other@example.test")
    other.display_name = '"><script>alert(1)</script>'

    markup = _user_rows([actor, other], current_user=actor)

    assert markup.count("disabled") == 2
    assert "<script>" not in markup
    assert "&lt;script&gt;" in markup
    assert 'value="super_admin" selected' in markup
