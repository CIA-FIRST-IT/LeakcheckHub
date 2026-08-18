"""Masked-only user finding projections and serializers.

This module deliberately does not import the findings ORM model. Its input type contains only the
small safe projection that an ordinary portal response may expose.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date, datetime


@dataclass(frozen=True, slots=True)
class UserFindingProjection:
    id: uuid.UUID
    source: str
    breach_date: date | None
    fields: tuple[str, ...]
    origin: str | None
    password_mask: str | None
    remediated_at: datetime | None
    re_leaked: bool
    first_seen_at: datetime
    last_seen_at: datetime


def serialize_user_finding(item: UserFindingProjection) -> dict[str, object]:
    """Return the complete allow-listed user shape; no credential payload can enter it."""

    return {
        "id": str(item.id),
        "source": item.source,
        "breach_date": item.breach_date.isoformat() if item.breach_date else None,
        "fields": list(item.fields),
        "origin": item.origin,
        "password_mask": item.password_mask,
        "remediated": item.remediated_at is not None,
        "re_leaked": item.re_leaked,
        "first_seen_at": item.first_seen_at.isoformat(timespec="seconds"),
        "last_seen_at": item.last_seen_at.isoformat(timespec="seconds"),
        "guidance": remediation_guidance(item),
    }


def remediation_guidance(item: UserFindingProjection) -> str:
    if item.password_mask:
        return (
            "Change this password anywhere it was reused, enable MFA, then mark the exposure fixed."
        )
    if any(field.casefold() in {"email", "phone", "address", "name"} for field in item.fields):
        return (
            "Treat unexpected messages as suspicious and verify requests through a known channel."
        )
    return "Review the exposed fields and follow your security team's remediation guidance."
