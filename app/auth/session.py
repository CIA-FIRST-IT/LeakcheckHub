"""Opaque, server-side session issuance, verification, and revocation.

The browser receives an unguessable 256-bit token.  PostgreSQL receives only its SHA-256 digest, so
a database read cannot be used as a bearer credential.  All callers must use the supplied request
database transaction (``get_db_session`` commits it after a successful request).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any, Final, cast

from fastapi import Response
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.models import Session, User

SESSION_COOKIE_NAME: Final = "__Host-leakcheck-session"
_TOKEN_BYTES: Final = 32
_TOKEN_LENGTH: Final = 43
_TOKEN_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """The one-time browser credential and the timestamp that bounds its lifetime."""

    token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedSession:
    """An active session together with the user it authenticates."""

    user: User
    expires_at: datetime


class SessionManager:
    """Manage opaque sessions without ever retaining or logging cleartext tokens."""

    def __init__(self, settings: Settings) -> None:
        self._idle_ttl = timedelta(seconds=settings.session_idle_ttl_seconds)
        self._absolute_ttl = timedelta(seconds=settings.session_absolute_ttl_seconds)
        self._metadata_key = settings.session_secret.get_secret_value().encode("utf-8")

    async def issue(
        self,
        db: AsyncSession,
        *,
        user_id: uuid.UUID,
        client_ip: str,
        user_agent: str | None,
        now: datetime | None = None,
    ) -> IssuedSession:
        """Create a session with independent idle and absolute expiration deadlines."""

        issued_at = _utc_now(now)
        raw_token = secrets.token_urlsafe(_TOKEN_BYTES)
        expires_at = issued_at + self._absolute_ttl
        session = Session(
            id_hash=_token_hash(raw_token),
            user_id=user_id,
            created_at=issued_at,
            expires_at=expires_at,
            last_seen_at=issued_at,
            idle_expires_at=min(issued_at + self._idle_ttl, expires_at),
            ip_hash=self._metadata_hash(_canonical_ip(client_ip)),
            ua_hash=self._metadata_hash(user_agent or ""),
        )
        db.add(session)
        await db.flush()
        return IssuedSession(token=raw_token, expires_at=expires_at)

    async def verify(
        self,
        db: AsyncSession,
        *,
        token: str | None,
        now: datetime | None = None,
    ) -> VerifiedSession | None:
        """Return an active user and slide only a valid session's idle deadline.

        The row lock serialises this update with explicit revocation.  The absolute deadline is
        never extended, even for a session that is used continuously.
        """

        token_digest = _validated_token_hash(token)
        if token_digest is None:
            return None

        current_time = _utc_now(now)
        result = await db.execute(
            select(Session, User)
            .join(User, User.id == Session.user_id)
            .where(Session.id_hash == token_digest)
            .with_for_update()
        )
        row = result.one_or_none()
        if row is None:
            return None

        session, user = row
        if (
            session.revoked_at is not None
            or not user.is_active
            or current_time >= session.expires_at
            or current_time >= session.idle_expires_at
        ):
            return None

        session.last_seen_at = current_time
        session.idle_expires_at = min(session.expires_at, current_time + self._idle_ttl)
        await db.flush()
        return VerifiedSession(user=user, expires_at=session.expires_at)

    async def revoke(
        self,
        db: AsyncSession,
        *,
        token: str | None,
        now: datetime | None = None,
    ) -> bool:
        """Revoke one matching session.  It is safe to call repeatedly."""

        token_digest = _validated_token_hash(token)
        if token_digest is None:
            return False

        result = await db.execute(
            select(Session).where(Session.id_hash == token_digest).with_for_update()
        )
        session = result.scalar_one_or_none()
        if session is None or session.revoked_at is not None:
            return False

        session.revoked_at = _utc_now(now)
        await db.flush()
        return True

    async def revoke_all(
        self,
        db: AsyncSession,
        *,
        user_id: uuid.UUID,
        now: datetime | None = None,
    ) -> int:
        """Revoke every currently active session for a user and return the count changed."""

        result = await db.execute(
            update(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .values(revoked_at=_utc_now(now))
        )
        await db.flush()
        return cast(CursorResult[Any], result).rowcount or 0

    def set_cookie(
        self, response: Response, issued: IssuedSession, *, now: datetime | None = None
    ) -> None:
        """Attach the bearer token with the browser protections required by the plan."""

        max_age = max(0, int((issued.expires_at - _utc_now(now)).total_seconds()))
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=issued.token,
            max_age=max_age,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )

    def clear_cookie(self, response: Response) -> None:
        """Remove the cookie using the same scope and security attributes used to set it."""

        response.delete_cookie(
            key=SESSION_COOKIE_NAME,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )

    def _metadata_hash(self, value: str) -> bytes:
        """Key client fingerprints so a database read cannot dictionary-attack them."""

        return hmac.new(self._metadata_key, value.encode("utf-8"), hashlib.sha256).digest()


@lru_cache
def get_session_manager() -> SessionManager:
    """Return the validated process-wide session manager."""

    return SessionManager(get_settings())


def _token_hash(token: str) -> bytes:
    """Hash the exact ASCII bearer token stored only in the browser."""

    return hashlib.sha256(token.encode("ascii")).digest()


def _validated_token_hash(token: str | None) -> bytes | None:
    """Reject malformed cookie values before they cause a database lookup."""

    if token is None or not _TOKEN_PATTERN.fullmatch(token) or len(token) != _TOKEN_LENGTH:
        return None
    return _token_hash(token)


def _canonical_ip(value: str) -> str:
    """Normalise IPv4 and IPv6 input before calculating its keyed fingerprint."""

    return str(ipaddress.ip_address(value))


def _utc_now(value: datetime | None) -> datetime:
    """Use timezone-aware UTC timestamps so expiration comparisons are unambiguous."""

    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("session timestamps must be timezone-aware")
    return current.astimezone(UTC)
