"""Organisation branding tests.

The logo is uploaded by an administrator and rendered on a page served to anonymous visitors, so
format validation is a security control rather than a convenience.
"""

from __future__ import annotations

import pytest

from app.branding import MAX_LOGO_BYTES, LogoRejected, OrganisationBranding, detect_content_type

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
_GIF = b"GIF89a" + b"\x00" * 32
_WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 16


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (_PNG, "image/png"),
        (_JPEG, "image/jpeg"),
        (_GIF, "image/gif"),
        (_WEBP, "image/webp"),
    ],
)
def test_accepted_raster_formats_are_identified_from_their_bytes(
    data: bytes, expected: str
) -> None:
    assert detect_content_type(data) == expected


def test_svg_is_rejected_because_it_can_carry_script() -> None:
    """An SVG logo on the anonymous sign-in page would be a stored-XSS primitive."""

    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'

    with pytest.raises(LogoRejected, match="SVG is not"):
        detect_content_type(svg)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not-an-image-at-all",
        b"<!doctype html><html></html>",
        b"%PDF-1.7\n",
    ],
)
def test_anything_that_is_not_an_accepted_image_is_rejected(data: bytes) -> None:
    with pytest.raises(LogoRejected):
        detect_content_type(data)


def test_an_oversized_logo_is_rejected_before_any_format_check() -> None:
    with pytest.raises(LogoRejected, match="exceeds"):
        detect_content_type(_PNG + b"\x00" * MAX_LOGO_BYTES)


def test_the_display_name_falls_back_when_no_organisation_is_set() -> None:
    assert OrganisationBranding().display_name == "LeakCheck Hub"
    assert OrganisationBranding(name="CIA FIRST").display_name == "CIA FIRST"
