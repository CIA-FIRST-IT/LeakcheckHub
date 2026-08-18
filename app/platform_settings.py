"""Encrypted, database-backed operational configuration.

Database connectivity and the root encryption/session keys are deployment bootstrap material.  Every
third-party integration is instead blank by default and managed by a super-admin through this store.
"""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from enum import StrEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import PlatformSetting

_NONCE_BYTES = 12
_SCHEMA_VERSION = 1


class SettingKey(StrEnum):
    LEAKCHECK_API_KEY = "leakcheck_api_key"
    LEAKCHECK_RPS = "leakcheck_rps"
    LEAKCHECK_CONCURRENCY = "leakcheck_concurrency"
    LEAKCHECK_MAX_RESPONSE_BYTES = "leakcheck_max_response_bytes"
    SELF_CHECK_COOLDOWN_SECONDS = "self_check_cooldown_seconds"
    GOOGLE_CLIENT_ID = "google_client_id"
    GOOGLE_CLIENT_SECRET = "google_client_secret"  # noqa: S105  # nosec B105
    GOOGLE_REDIRECT_URI = "google_redirect_uri"
    GOOGLE_WORKSPACE_DOMAINS = "google_workspace_domains"
    GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON = "google_workspace_service_account_json"
    GOOGLE_WORKSPACE_DELEGATED_ADMIN = "google_workspace_delegated_admin"
    WAZUH_URL = "wazuh_url"
    WAZUH_USERNAME = "wazuh_username"
    WAZUH_PASSWORD = "wazuh_password"  # noqa: S105  # nosec B105
    DFIR_IRIS_URL = "dfir_iris_url"
    DFIR_IRIS_API_KEY = "dfir_iris_api_key"
    DFIR_IRIS_CUSTOMER_ID = "dfir_iris_customer_id"
    SMTP_HOST = "smtp_host"
    SMTP_PORT = "smtp_port"
    SMTP_USERNAME = "smtp_username"
    SMTP_PASSWORD = "smtp_password"  # noqa: S105  # nosec B105
    SMTP_FROM = "smtp_from"
    SMTP_SECURITY = "smtp_security"
    PUBLIC_BASE_URL = "public_base_url"
    NOTIFY_DRY_RUN = "notify_dry_run"
    NOTIFY_COOLDOWN_SECONDS = "notify_cooldown_seconds"
    SOC_EMAIL = "soc_email"


SECRET_KEYS = frozenset(
    {
        SettingKey.LEAKCHECK_API_KEY,
        SettingKey.GOOGLE_CLIENT_SECRET,
        SettingKey.GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON,
        SettingKey.WAZUH_PASSWORD,
        SettingKey.DFIR_IRIS_API_KEY,
        SettingKey.SMTP_PASSWORD,
    }
)


class PlatformSettingError(Exception):
    """Stored configuration is absent, invalid, or cannot be authenticated."""


class PlatformSettingsStore:
    """Read and atomically replace encrypted settings."""

    def __init__(self, settings: Settings) -> None:
        encoded = settings.data_key.get_secret_value()
        padded = encoded + ("=" * (-len(encoded) % 4))
        self._cipher = AESGCM(base64.urlsafe_b64decode(padded))

    async def read(self, db: AsyncSession, key: SettingKey) -> str | None:
        result = await db.execute(select(PlatformSetting).where(PlatformSetting.key == key.value))
        row = result.scalar_one_or_none()
        if row is None:
            return None
        try:
            plaintext = self._cipher.decrypt(
                row.nonce, row.ciphertext, self._aad(key, row.schema_version)
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise PlatformSettingError(f"cannot decrypt platform setting {key.value}") from exc

    async def read_many(
        self, db: AsyncSession, keys: set[SettingKey] | frozenset[SettingKey]
    ) -> dict[SettingKey, str]:
        values: dict[SettingKey, str] = {}
        for key in keys:
            value = await self.read(db, key)
            if value is not None:
                values[key] = value
        return values

    async def write_many(
        self,
        db: AsyncSession,
        values: dict[SettingKey, str | None],
        *,
        actor_id: uuid.UUID,
    ) -> None:
        """Replace supplied values; blank secret fields preserve the existing secret."""

        for key, value in values.items():
            if value is None or (key in SECRET_KEYS and value == ""):
                continue
            result = await db.execute(
                select(PlatformSetting).where(PlatformSetting.key == key.value).with_for_update()
            )
            row = result.scalar_one_or_none()
            nonce = secrets.token_bytes(_NONCE_BYTES)
            ciphertext = self._cipher.encrypt(
                nonce, value.encode("utf-8"), self._aad(key, _SCHEMA_VERSION)
            )
            if row is None:
                db.add(
                    PlatformSetting(
                        key=key.value,
                        ciphertext=ciphertext,
                        nonce=nonce,
                        schema_version=_SCHEMA_VERSION,
                        updated_by=actor_id,
                    )
                )
            else:
                row.ciphertext = ciphertext
                row.nonce = nonce
                row.schema_version = _SCHEMA_VERSION
                row.updated_by = actor_id
        await db.flush()

    async def configured_state(self, db: AsyncSession) -> dict[str, bool]:
        result = await db.execute(select(PlatformSetting.key))
        configured = set(result.scalars())
        return {key.value: key.value in configured for key in SettingKey}

    @staticmethod
    def encode_domains(domains: list[str]) -> str:
        return json.dumps(domains, separators=(",", ":"))

    @staticmethod
    def decode_domains(value: str) -> tuple[str, ...]:
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PlatformSettingError("invalid stored Google domain list") from exc
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            raise PlatformSettingError("invalid stored Google domain list")
        return tuple(decoded)

    @staticmethod
    def _aad(key: SettingKey, schema_version: int) -> bytes:
        return f"leakcheck/platform-setting/{schema_version}/{key.value}".encode("ascii")
