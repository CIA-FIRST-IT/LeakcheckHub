"""Minimal deployment bootstrap configuration.

Operational integrations live encrypted in PostgreSQL and are managed through the application.
"""

from __future__ import annotations

import base64
import binascii
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Self

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


class Settings(BaseSettings):
    """Validated application configuration.

    Only values needed before PostgreSQL can be read, or needed to decrypt PostgreSQL-held settings,
    belong here. Validation is intentionally eager before an HTTP listener is exposed.
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
