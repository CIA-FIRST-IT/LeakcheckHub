"""Append-only audit event creation."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import uuid

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import AuditLog


async def audit_event(
    db: AsyncSession,
    request: Request,
    settings: Settings,
    *,
    action: str,
    actor_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    meta: dict[str, object] | None = None,
) -> AuditLog:
    """Append a non-secret event with a keyed client-address fingerprint."""

    client_ip = request.client.host if request.client is not None else ""
    try:
        canonical_ip = ipaddress.ip_address(client_ip).compressed.encode("ascii")
    except ValueError:
        canonical_ip = b"invalid"
    key = hmac.new(
        settings.session_secret.get_secret_value().encode("utf-8"),
        b"leakcheck/audit-ip/v1",
        hashlib.sha256,
    ).digest()
    event = AuditLog(
        id=uuid.uuid4(),
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_hash=hmac.new(key, canonical_ip, hashlib.sha256).digest(),
        meta=meta or {},
    )
    db.add(event)
    await db.flush()
    return event
