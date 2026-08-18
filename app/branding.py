"""Organisation name and logo shown on the unauthenticated landing page.

Only raster formats are accepted. SVG is rejected deliberately: it is an XML document that can
carry script and external references, and this image is rendered on a page served to anonymous
visitors, so accepting it would hand an uploader a stored-XSS primitive.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Branding

MAX_LOGO_BYTES = 1024 * 1024

# (magic prefix, offset, content type). Checked against the bytes, never against a supplied name.
_SIGNATURES: tuple[tuple[bytes, int, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"WEBP", 8, "image/webp"),
)


class LogoRejected(Exception):
    """The uploaded bytes are not an accepted raster image."""


@dataclass(frozen=True)
class OrganisationBranding:
    name: str | None = None
    has_logo: bool = False
    logo_sha256: str | None = None

    @property
    def display_name(self) -> str:
        return self.name or "LeakCheck Hub"


def detect_content_type(data: bytes) -> str:
    """Identify an accepted raster image from its bytes, rejecting everything else."""

    if not data:
        raise LogoRejected("the logo is empty")
    if len(data) > MAX_LOGO_BYTES:
        raise LogoRejected(f"the logo exceeds {MAX_LOGO_BYTES // 1024} KB")
    for prefix, offset, content_type in _SIGNATURES:
        if data[offset : offset + len(prefix)] == prefix:
            return content_type
    raise LogoRejected("only PNG, JPEG, GIF, and WebP images are accepted (SVG is not)")


async def load(db: AsyncSession) -> OrganisationBranding:
    """Read the branding row, returning defaults when nothing has been configured."""

    row = (await db.execute(select(Branding).where(Branding.id == 1))).scalar_one_or_none()
    if row is None:
        return OrganisationBranding()
    return OrganisationBranding(
        name=row.organization_name,
        has_logo=row.logo is not None,
        logo_sha256=row.logo_sha256,
    )


async def load_logo(db: AsyncSession) -> tuple[bytes, str, str] | None:
    """Return the stored logo bytes, content type, and digest for the public image route."""

    row = (await db.execute(select(Branding).where(Branding.id == 1))).scalar_one_or_none()
    if row is None or row.logo is None:
        return None
    return row.logo, row.logo_content_type or "application/octet-stream", row.logo_sha256 or ""


async def _row(db: AsyncSession) -> Branding:
    row = (await db.execute(select(Branding).where(Branding.id == 1))).scalar_one_or_none()
    if row is None:
        row = Branding(id=1)
        db.add(row)
    return row


async def set_name(db: AsyncSession, name: str | None) -> None:
    row = await _row(db)
    cleaned = (name or "").strip()
    row.organization_name = cleaned or None
    await db.flush()


async def set_logo(db: AsyncSession, data: bytes) -> str:
    """Store a validated logo and return its content type."""

    content_type = detect_content_type(data)
    row = await _row(db)
    row.logo = data
    row.logo_content_type = content_type
    row.logo_sha256 = hashlib.sha256(data).hexdigest()
    await db.flush()
    return content_type


async def clear_logo(db: AsyncSession) -> None:
    row = await _row(db)
    row.logo = None
    row.logo_content_type = None
    row.logo_sha256 = None
    await db.flush()
