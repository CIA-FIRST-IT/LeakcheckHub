"""Enrollment QR rendering tests."""

from __future__ import annotations

from app.auth.local import build_totp_provisioning_uri, generate_totp_secret
from app.totp_qr import provisioning_qr_svg

_SECRET = generate_totp_secret()
_URI = build_totp_provisioning_uri(email="admin@example.test", secret=_SECRET)


def test_the_qr_is_a_self_contained_inline_svg_element() -> None:
    """It is embedded in the page, so it must carry no XML prologue and fetch nothing."""

    svg = provisioning_qr_svg(_URI)

    assert svg.lstrip().startswith("<svg")
    assert "<?xml" not in svg
    assert "http://www.w3.org/2000/svg" in svg
    for scheme in ("src=", "href=", "url("):
        assert scheme not in svg


def test_the_secret_never_appears_in_the_rendered_markup() -> None:
    """A scannable code must not also be a copy-pasteable secret in the page source."""

    svg = provisioning_qr_svg(_URI)

    assert _SECRET not in svg
    assert "otpauth" not in svg


def test_rendering_is_deterministic_and_secret_specific() -> None:
    other = build_totp_provisioning_uri(email="admin@example.test", secret=generate_totp_secret())

    assert provisioning_qr_svg(_URI) == provisioning_qr_svg(_URI)
    assert provisioning_qr_svg(other) != provisioning_qr_svg(_URI)
