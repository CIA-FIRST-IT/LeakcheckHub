"""Render a TOTP provisioning URI as an inline SVG QR code.

The SVG is embedded directly in the page rather than served as its own resource: an enrollment
secret must never become a cacheable URL, appear in an access log, or be fetched over a separate
connection. It also keeps the page working under a strict content-security policy.
"""

from __future__ import annotations

import io

import segno

_SCALE = 4
_BORDER = 2


def provisioning_qr_svg(uri: str) -> str:
    """Return a self-contained, theme-neutral SVG for an ``otpauth://`` URI."""

    buffer = io.BytesIO()
    segno.make(uri, error="m").save(
        buffer,
        kind="svg",
        scale=_SCALE,
        border=_BORDER,
        dark="#111111",
        light="#ffffff",
        xmldecl=False,
        svgns=True,
    )
    return buffer.getvalue().decode("utf-8")
