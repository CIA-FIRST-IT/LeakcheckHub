"""Configuration loaded exclusively from environment variables or a local .env file."""

from __future__ import annotations

import base64
import binascii
import re
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


_KNOWN_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "change-me",
        "replace-me",
        "replace-with-a-long-random-password",
        "replace-with-at-least-32-random-characters",
        "replace-with-a-base64url-encoded-32-byte-key",
    }
)
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class Settings(BaseSettings):
    """Validated application configuration.

    Validation is intentionally eager at process start. A missing or placeholder secret must stop a
    process before it can expose an HTTP listener.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="LC_",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Environment = Environment.DEVELOPMENT
    database_url: str
    session_secret: SecretStr
    session_idle_ttl_seconds: Annotated[int, Field(ge=1)] = 60 * 60
    session_absolute_ttl_seconds: Annotated[int, Field(ge=1)] = 12 * 60 * 60
    admin_login_max_failures: Annotated[int, Field(ge=1, le=20)] = 5
    admin_login_lockout_seconds: Annotated[int, Field(ge=60, le=24 * 60 * 60)] = 15 * 60
    admin_login_ip_max_failures: Annotated[int, Field(ge=1, le=100)] = 10
    admin_login_ip_window_seconds: Annotated[int, Field(ge=60, le=24 * 60 * 60)] = 15 * 60
    admin_login_ip_lockout_seconds: Annotated[int, Field(ge=60, le=24 * 60 * 60)] = 15 * 60
    google_client_id: str
    google_client_secret: SecretStr
    google_redirect_uri: str
    google_workspace_domains: Annotated[tuple[str, ...], NoDecode]
    data_key: SecretStr
    trusted_hosts: Annotated[tuple[str, ...], NoDecode] = ("localhost", "127.0.0.1")

    @field_validator("database_url")
    @classmethod
    def database_url_must_be_async_postgres(cls, value: str) -> str:
        if not value.startswith("postgresql+asyncpg://"):
            msg = "LC_DATABASE_URL must use postgresql+asyncpg://"
            raise ValueError(msg)
        return value

    @field_validator("session_secret")
    @classmethod
    def session_secret_must_be_strong(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if secret.casefold() in _KNOWN_PLACEHOLDERS or secret.startswith("replace-with-"):
            raise ValueError("LC_SESSION_SECRET must not be a placeholder")
        if len(secret.encode("utf-8")) < 32:
            raise ValueError("LC_SESSION_SECRET must contain at least 32 bytes")
        return value

    @field_validator("google_client_id")
    @classmethod
    def google_client_id_must_not_be_empty(cls, value: str) -> str:
        if (
            not value.strip()
            or value.casefold() in _KNOWN_PLACEHOLDERS
            or value.startswith("replace-with-")
        ):
            raise ValueError("LC_GOOGLE_CLIENT_ID must be configured")
        return value

    @field_validator("google_client_secret")
    @classmethod
    def google_client_secret_must_not_be_a_placeholder(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if (
            not secret
            or secret.casefold() in _KNOWN_PLACEHOLDERS
            or secret.startswith("replace-with-")
        ):
            raise ValueError("LC_GOOGLE_CLIENT_SECRET must be configured")
        return value

    @field_validator("google_redirect_uri")
    @classmethod
    def google_redirect_uri_must_be_safe(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ValueError("LC_GOOGLE_REDIRECT_URI must be a valid URL") from exc
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        is_local_http = parsed.scheme == "http" and parsed.hostname in local_hosts
        if (
            parsed.scheme not in {"https", "http"}
            or (parsed.scheme != "https" and not is_local_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/auth/google/callback"
        ):
            raise ValueError(
                "LC_GOOGLE_REDIRECT_URI must use HTTPS (or local HTTP) and end in "
                "/auth/google/callback"
            )
        return value

    @field_validator("data_key")
    @classmethod
    def data_key_must_be_aes_256_key(cls, value: SecretStr) -> SecretStr:
        encoded = value.get_secret_value()
        if encoded.casefold() in _KNOWN_PLACEHOLDERS or encoded.startswith("replace-with-"):
            raise ValueError("LC_DATA_KEY must not be a placeholder")
        try:
            padded = encoded + ("=" * (-len(encoded) % 4))
            key = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise ValueError("LC_DATA_KEY must be base64-url encoded") from exc
        if len(key) != 32:
            raise ValueError("LC_DATA_KEY must decode to exactly 32 bytes")
        return value

    @field_validator("trusted_hosts", mode="before")
    @classmethod
    def parse_trusted_hosts(cls, value: str | tuple[str, ...] | list[str]) -> tuple[str, ...]:
        if isinstance(value, str):
            return tuple(host.strip() for host in value.split(",") if host.strip())
        return tuple(value)

    @field_validator("google_workspace_domains", mode="before")
    @classmethod
    def parse_google_workspace_domains(
        cls, value: str | tuple[str, ...] | list[str]
    ) -> tuple[str, ...]:
        raw_domains = value.split(",") if isinstance(value, str) else value
        domains: list[str] = []
        for raw_domain in raw_domains:
            domain = raw_domain.strip().casefold().rstrip(".")
            if not domain or domain.startswith("replace-with-"):
                raise ValueError("LC_GOOGLE_WORKSPACE_DOMAINS must contain explicit domains")
            try:
                ascii_domain = domain.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("LC_GOOGLE_WORKSPACE_DOMAINS contains an invalid domain") from exc
            if "." not in ascii_domain or any(
                _DOMAIN_LABEL.fullmatch(label) is None for label in ascii_domain.split(".")
            ):
                raise ValueError("LC_GOOGLE_WORKSPACE_DOMAINS contains an invalid domain")
            domains.append(ascii_domain)
        if not domains:
            raise ValueError("LC_GOOGLE_WORKSPACE_DOMAINS must not be empty")
        return tuple(dict.fromkeys(domains))

    @model_validator(mode="after")
    def require_explicit_production_hosts(self) -> Self:
        if self.session_idle_ttl_seconds > self.session_absolute_ttl_seconds:
            raise ValueError("LC_SESSION_IDLE_TTL_SECONDS must not exceed the absolute TTL")
        if not self.trusted_hosts or "*" in self.trusted_hosts:
            raise ValueError("LC_TRUSTED_HOSTS must be a non-empty explicit host allow-list")
        if self.environment is Environment.PRODUCTION and any(
            host in {"localhost", "127.0.0.1"} for host in self.trusted_hosts
        ):
            raise ValueError("LC_TRUSTED_HOSTS must not contain local hosts in production")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the singleton process configuration after validation."""

    return Settings()
