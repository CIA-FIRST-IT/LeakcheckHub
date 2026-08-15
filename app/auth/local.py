"""Local super-admin credentials with Argon2id, encrypted TOTP, and durable throttling.

This module intentionally owns the only path that loads ``AdminCredential``'s deferred secret
columns.  It neither logs nor returns a submitted password.  The CLI in
``app.create_superadmin`` is the sole provisioning path.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final
from urllib.parse import quote, urlencode

from argon2 import PasswordHasher, Type, exceptions
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from app.config import Settings
from app.models import AdminCredential, AdminLoginRateLimit, User, UserRole, UserSource

_ARGON2_HASHER: Final = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_DUMMY_VERIFIER: Final = (
    "$argon2id$v=19$m=65536,t=3,p=4$MIIRqgvgQbgj220jfp0MPA$YfwJSVjtjSU0zzV/P3S9nnQ/"
    "USre2wvJMjfCIjrTQbg"
)
_TOTP_SECRET_BYTES: Final = 20
_TOTP_DIGITS: Final = 6
_TOTP_PERIOD_SECONDS: Final = 30
_TOTP_VALID_WINDOWS: Final = 1
_TOTP_NONCE_BYTES: Final = 12
_MIN_PASSWORD_BYTES: Final = 15
_MAX_PASSWORD_BYTES: Final = 1024
_MAX_EMAIL_LENGTH: Final = 255
_MAX_DISPLAY_NAME_LENGTH: Final = 255
_EMAIL_PATTERN: Final = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


class LocalAuthenticationError(Exception):
    """A deliberately non-sensitive local authentication or TOTP-storage failure."""


class SuperAdminAlreadyExistsError(Exception):
    """The bootstrap command must not silently modify an existing account."""


@dataclass(frozen=True, slots=True)
class LocalAuthenticationResult:
    """The authenticated account, if all factors and throttles have passed."""

    user: User | None


@dataclass(frozen=True, slots=True)
class CreatedSuperAdmin:
    """A one-time TOTP seed result.  Its representation omits the seed."""

    user: User
    totp_secret: str = field(repr=False)


def hash_password(password: str) -> str:
    """Validate and hash a bootstrap password with explicitly configured Argon2id."""

    _validate_new_password(password)
    return _ARGON2_HASHER.hash(password)


def generate_totp_secret() -> str:
    """Generate an RFC 6238-compatible 160-bit Base32 TOTP seed."""

    return base64.b32encode(secrets.token_bytes(_TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def totp_code(secret: str, *, now: datetime | None = None) -> str:
    """Return the current six-digit RFC 6238 TOTP value for a valid Base32 seed."""

    counter = int(_utc_now(now).timestamp()) // _TOTP_PERIOD_SECONDS
    if counter < 0:
        raise LocalAuthenticationError
    key = _totp_key(secret)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()  # noqa: S324
    offset = digest[-1] & 0x0F
    truncated = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFF_FFFF
    return f"{truncated % (10**_TOTP_DIGITS):0{_TOTP_DIGITS}d}"


def verify_totp(secret: str, supplied_code: str, *, now: datetime | None = None) -> bool:
    """Verify a current TOTP code in constant time, allowing only one clock-skew window each way."""

    if (
        len(supplied_code) != _TOTP_DIGITS
        or not supplied_code.isascii()
        or not supplied_code.isdigit()
    ):
        return False
    current = _utc_now(now)
    try:
        expected_codes = tuple(
            totp_code(secret, now=current + timedelta(seconds=offset * _TOTP_PERIOD_SECONDS))
            for offset in range(-_TOTP_VALID_WINDOWS, _TOTP_VALID_WINDOWS + 1)
        )
    except LocalAuthenticationError:
        return False
    return bool(sum(hmac.compare_digest(supplied_code, expected) for expected in expected_codes))


def encrypt_totp_secret(settings: Settings, *, user_id: uuid.UUID, secret: str) -> bytes:
    """Encrypt a valid TOTP seed with AES-256-GCM and bind it to its account UUID."""

    _totp_key(secret)
    nonce = secrets.token_bytes(_TOTP_NONCE_BYTES)
    ciphertext = AESGCM(_data_key(settings)).encrypt(
        nonce, secret.encode("ascii"), _totp_aad(user_id)
    )
    return nonce + ciphertext


def decrypt_totp_secret(settings: Settings, *, user_id: uuid.UUID, encrypted: bytes) -> str:
    """Decrypt and validate a TOTP seed, exposing only a generic failure for any tampering."""

    if len(encrypted) <= _TOTP_NONCE_BYTES:
        raise LocalAuthenticationError
    try:
        plaintext = AESGCM(_data_key(settings)).decrypt(
            encrypted[:_TOTP_NONCE_BYTES], encrypted[_TOTP_NONCE_BYTES:], _totp_aad(user_id)
        )
        secret = plaintext.decode("ascii")
        _totp_key(secret)
    except (InvalidTag, UnicodeDecodeError, LocalAuthenticationError) as exc:
        raise LocalAuthenticationError from exc
    return secret


def build_totp_provisioning_uri(*, email: str, secret: str) -> str:
    """Build the standard URI printed once by the local provisioning CLI."""

    _totp_key(secret)
    issuer = "LeakCheck SOC Portal"
    label = quote(f"{issuer}:{normalise_admin_email(email)}", safe="")
    return f"otpauth://totp/{label}?{urlencode({'secret': secret, 'issuer': issuer})}"


async def create_superadmin(
    db: AsyncSession,
    *,
    settings: Settings,
    email: str,
    display_name: str,
    password: str,
) -> CreatedSuperAdmin:
    """Create an active manual super-admin and return its one-time TOTP provisioning seed."""

    normalised_email = normalise_admin_email(email)
    normalised_name = normalise_display_name(display_name)
    existing = await db.execute(
        select(User).where(User.email == normalised_email).with_for_update()
    )
    if existing.scalar_one_or_none() is not None:
        raise SuperAdminAlreadyExistsError

    user = User(
        id=uuid.uuid4(),
        email=normalised_email,
        display_name=normalised_name,
        role=UserRole.SUPER_ADMIN,
        is_active=True,
        source=UserSource.MANUAL,
    )
    secret = generate_totp_secret()
    credential = AdminCredential(
        user_id=user.id,
        password_hash=hash_password(password),
        totp_secret_enc=encrypt_totp_secret(settings, user_id=user.id, secret=secret),
    )
    db.add(user)
    db.add(credential)
    await db.flush()
    return CreatedSuperAdmin(user=user, totp_secret=secret)


class LocalAuthenticator:
    """Authenticate only active super-admins while enforcing account and IP throttles."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._account_max_failures = settings.admin_login_max_failures
        self._account_lockout = timedelta(seconds=settings.admin_login_lockout_seconds)
        self._ip_max_failures = settings.admin_login_ip_max_failures
        self._ip_window = timedelta(seconds=settings.admin_login_ip_window_seconds)
        self._ip_lockout = timedelta(seconds=settings.admin_login_ip_lockout_seconds)
        self._ip_key = hmac.new(
            settings.session_secret.get_secret_value().encode("utf-8"),
            b"leakcheck/admin-login-ip/v1",
            hashlib.sha256,
        ).digest()

    async def authenticate(
        self,
        db: AsyncSession,
        *,
        username: str,
        password: str,
        totp_code: str,
        client_ip: str,
        now: datetime | None = None,
    ) -> LocalAuthenticationResult:
        """Return a user only after password, TOTP, account lockout, and IP throttle all pass."""

        current = _utc_now(now)
        try:
            ip_hash = self._ip_hash(client_ip)
        except LocalAuthenticationError:
            return LocalAuthenticationResult(user=None)
        rate_limit = await self._load_ip_limit(db, ip_hash=ip_hash, now=current)
        if rate_limit.blocked_until is not None and current < rate_limit.blocked_until:
            return LocalAuthenticationResult(user=None)
        self._reset_ip_limit_if_elapsed(rate_limit, now=current)

        email = _normalise_login_email(username)
        if email is None:
            _verify_dummy_password(password)
            self._record_ip_failure(rate_limit, now=current)
            await db.flush()
            return LocalAuthenticationResult(user=None)

        result = await db.execute(
            select(User, AdminCredential)
            .join(AdminCredential, AdminCredential.user_id == User.id)
            .options(
                undefer(AdminCredential.password_hash),
                undefer(AdminCredential.totp_secret_enc),
            )
            .where(User.email == email)
            .with_for_update()
        )
        row = result.one_or_none()
        if row is None:
            _verify_dummy_password(password)
            self._record_ip_failure(rate_limit, now=current)
            await db.flush()
            return LocalAuthenticationResult(user=None)

        user, credential = row
        if not user.is_active or user.role is not UserRole.SUPER_ADMIN:
            _verify_dummy_password(password)
            self._record_ip_failure(rate_limit, now=current)
            await db.flush()
            return LocalAuthenticationResult(user=None)

        if credential.locked_until is not None:
            if current < credential.locked_until:
                self._record_ip_failure(rate_limit, now=current)
                await db.flush()
                return LocalAuthenticationResult(user=None)
            credential.failed_attempts = 0
            credential.locked_until = None

        password_valid = _verify_password(credential.password_hash, password)
        totp_valid = False
        if password_valid:
            try:
                secret = decrypt_totp_secret(
                    self._settings,
                    user_id=user.id,
                    encrypted=credential.totp_secret_enc,
                )
                totp_valid = verify_totp(secret, totp_code, now=current)
            except LocalAuthenticationError:
                totp_valid = False

        if not password_valid or not totp_valid:
            credential.failed_attempts += 1
            if credential.failed_attempts >= self._account_max_failures:
                credential.locked_until = current + self._account_lockout
            self._record_ip_failure(rate_limit, now=current)
            await db.flush()
            return LocalAuthenticationResult(user=None)

        credential.failed_attempts = 0
        credential.locked_until = None
        if _password_needs_rehash(credential.password_hash):
            credential.password_hash = hash_password(password)
        user.last_login_at = current
        await db.flush()
        return LocalAuthenticationResult(user=user)

    async def _load_ip_limit(
        self, db: AsyncSession, *, ip_hash: bytes, now: datetime
    ) -> AdminLoginRateLimit:
        """Atomically create then lock the durable IP bucket for this login attempt."""

        await db.execute(
            postgresql_insert(AdminLoginRateLimit)
            .values(ip_hash=ip_hash, window_started_at=now, attempts=0)
            .on_conflict_do_nothing(index_elements=[AdminLoginRateLimit.ip_hash])
        )
        result = await db.execute(
            select(AdminLoginRateLimit)
            .where(AdminLoginRateLimit.ip_hash == ip_hash)
            .with_for_update()
        )
        return result.scalar_one()

    def _reset_ip_limit_if_elapsed(self, rate_limit: AdminLoginRateLimit, *, now: datetime) -> None:
        if rate_limit.blocked_until is not None and now >= rate_limit.blocked_until:
            rate_limit.attempts = 0
            rate_limit.blocked_until = None
            rate_limit.window_started_at = now
        elif now >= rate_limit.window_started_at + self._ip_window:
            rate_limit.attempts = 0
            rate_limit.window_started_at = now

    def _record_ip_failure(self, rate_limit: AdminLoginRateLimit, *, now: datetime) -> None:
        self._reset_ip_limit_if_elapsed(rate_limit, now=now)
        rate_limit.attempts += 1
        if rate_limit.attempts >= self._ip_max_failures:
            rate_limit.blocked_until = now + self._ip_lockout

    def _ip_hash(self, client_ip: str) -> bytes:
        canonical_ip = _canonical_ip(client_ip)
        return hmac.new(self._ip_key, canonical_ip.encode("ascii"), hashlib.sha256).digest()


def normalise_admin_email(email: str) -> str:
    """Constrain locally provisioned usernames to a small, ASCII email address subset."""

    normalised = email.strip().lower()
    if (
        not normalised.isascii()
        or len(normalised) > _MAX_EMAIL_LENGTH
        or _EMAIL_PATTERN.fullmatch(normalised) is None
    ):
        raise LocalAuthenticationError
    return normalised


def normalise_display_name(display_name: str) -> str:
    """Validate a non-empty bounded bootstrap display name."""

    normalised = display_name.strip()
    if not normalised or len(normalised) > _MAX_DISPLAY_NAME_LENGTH:
        raise LocalAuthenticationError
    return normalised


def _normalise_login_email(email: str) -> str | None:
    try:
        return normalise_admin_email(email)
    except LocalAuthenticationError:
        return None


def _validate_new_password(password: str) -> None:
    try:
        length = len(password.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise LocalAuthenticationError from exc
    if not _MIN_PASSWORD_BYTES <= length <= _MAX_PASSWORD_BYTES:
        raise LocalAuthenticationError


def _verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ARGON2_HASHER.verify(password_hash, password)
    except (exceptions.InvalidHashError, exceptions.VerificationError):
        return False


def _verify_dummy_password(password: str) -> None:
    """Spend a normal Argon2id verification for non-existent or ineligible accounts."""

    _verify_password(_DUMMY_VERIFIER, password)


def _password_needs_rehash(password_hash: str) -> bool:
    try:
        return _ARGON2_HASHER.check_needs_rehash(password_hash)
    except exceptions.InvalidHashError:
        return False


def _data_key(settings: Settings) -> bytes:
    encoded = settings.data_key.get_secret_value()
    try:
        return base64.b64decode(
            (encoded + ("=" * (-len(encoded) % 4))).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise LocalAuthenticationError from exc


def _totp_key(secret: str) -> bytes:
    if not secret.isascii() or not 16 <= len(secret) <= 128:
        raise LocalAuthenticationError
    try:
        key = base64.b32decode(secret + ("=" * (-len(secret) % 8)), casefold=False)
    except binascii.Error as exc:
        raise LocalAuthenticationError from exc
    if len(key) != _TOTP_SECRET_BYTES:
        raise LocalAuthenticationError
    return key


def _totp_aad(user_id: uuid.UUID) -> bytes:
    return b"leakcheck/admin-totp/v1/" + user_id.bytes


def _canonical_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise LocalAuthenticationError from exc


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return current.astimezone(UTC)
