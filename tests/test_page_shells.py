"""Every authenticated page shell must offer the same baseline controls.

The portal renders from more than one shell — analysts and super-admins share one, ordinary users
have their own — so a header change applied to one silently misses the other. That is exactly how
signed-in users ended up with no way to sign out.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest

from app.analyst_ui import page as analyst_page
from app.models import User, UserRole, UserSource
from app.user_ui import _page as portal_page

_APP = Path(__file__).resolve().parent.parent / "app"


def _user(role: UserRole) -> User:
    return User(
        id=uuid.uuid4(),
        email="person@example.test",
        display_name="Person",
        role=role,
        is_active=True,
        source=UserSource.GOOGLE,
    )


@pytest.mark.parametrize("role", [UserRole.USER, UserRole.ANALYST, UserRole.SUPER_ADMIN])
def test_the_analyst_shell_always_offers_sign_out(role: UserRole) -> None:
    assert 'id="sign-out"' in analyst_page("Scan", "<p>x</p>", user=_user(role))


def test_the_user_portal_shell_offers_sign_out() -> None:
    """Ordinary users reach the portal, never the analyst shell."""

    assert 'id="sign-out"' in portal_page("Portal", "<p>x</p>", _user(UserRole.USER))


def test_every_shell_requests_the_same_asset_versions() -> None:
    """A stale ?v= pin serves an older script, so a shell can carry markup its JS cannot drive."""

    sources = "\n".join((_APP / name).read_text() for name in ("analyst_ui.py", "user_ui.py"))
    for asset in ("analyst.css", "analyst.js"):
        versions = set(re.findall(rf"/static/{re.escape(asset)}\?v=(\d+)", sources))
        assert len(versions) == 1, f"{asset} is pinned to more than one version: {sorted(versions)}"
