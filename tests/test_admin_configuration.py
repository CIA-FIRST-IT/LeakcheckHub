"""Validation tests for the super-admin settings and user screens."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.models import UserRole
from app.routers.admin import SettingsUpdate, UserCreate, _workspace_help_dialog


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


def test_web_user_creation_cannot_create_another_superadmin() -> None:
    with pytest.raises(ValidationError, match="create-superadmin"):
        UserCreate(email="admin@example.test", display_name="Admin", role=UserRole.SUPER_ADMIN)


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
