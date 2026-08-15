"""Tests for fail-fast configuration validation."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from app.config import Environment, Settings


def valid_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "postgresql+asyncpg://runtime:password@postgres/leakcheck",
        "session_secret": "s" * 32,
        "google_client_id": "portal-client-id.apps.googleusercontent.com",
        "google_client_secret": "google-client-secret",
        "google_redirect_uri": "https://portal.example.test/auth/google/callback",
        "google_workspace_domains": ("example.test",),
        "data_key": base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        "trusted_hosts": ("testserver",),
    }
    values.update(overrides)
    return Settings(**values)


def test_accepts_valid_settings() -> None:
    settings = valid_settings()

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.trusted_hosts == ("testserver",)
    assert settings.session_idle_ttl_seconds == 60 * 60
    assert settings.session_absolute_ttl_seconds == 12 * 60 * 60


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_secret", "short"),
        ("session_secret", "replace-with-at-least-32-random-characters"),
        ("data_key", "not-base64"),
        ("data_key", base64.urlsafe_b64encode(b"too short").decode("ascii")),
        ("database_url", "postgresql://runtime:password@postgres/leakcheck"),
    ],
)
def test_rejects_unsafe_configuration(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        valid_settings(**{field: value})


def test_rejects_wildcard_host_allow_list() -> None:
    with pytest.raises(ValidationError, match="explicit host allow-list"):
        valid_settings(trusted_hosts=("*",))


def test_rejects_local_host_in_production() -> None:
    with pytest.raises(ValidationError, match="must not contain local hosts"):
        valid_settings(environment=Environment.PRODUCTION, trusted_hosts=("localhost",))


def test_rejects_idle_timeout_longer_than_absolute_timeout() -> None:
    with pytest.raises(ValidationError, match="must not exceed the absolute TTL"):
        valid_settings(session_idle_ttl_seconds=61, session_absolute_ttl_seconds=60)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("google_client_id", "replace-with-google-oauth-client-id"),
        ("google_client_secret", "replace-with-google-oauth-client-secret"),
        ("google_redirect_uri", "http://portal.example.test/auth/google/callback"),
        ("google_redirect_uri", "https://portal.example.test/not-the-callback"),
        ("google_workspace_domains", ("*.example.test",)),
        ("google_workspace_domains", ("replace-with-your-domain.example",)),
    ],
)
def test_rejects_unsafe_google_oidc_configuration(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        valid_settings(**{field: value})
