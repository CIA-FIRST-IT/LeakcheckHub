"""Every authenticated page shell must offer the same baseline controls.

The portal renders from more than one shell — analysts and super-admins share one, ordinary users
have their own — so a header change applied to one silently misses the other. That is exactly how
signed-in users ended up with no way to sign out.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from app.layout import page
from app.models import User, UserRole, UserSource

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
def test_every_role_can_sign_out(role: UserRole) -> None:
    assert 'id="sign-out"' in page("Scan", "<p>x</p>", user=_user(role))


def test_an_ordinary_user_sees_no_analyst_navigation() -> None:
    """A user reaching a shared page, such as MFA enrollment, must not be offered analyst links."""

    markup = page("Account security", "<p>x</p>", user=_user(UserRole.USER))

    assert 'href="/analyst"' not in markup
    assert 'href="/admin/settings"' not in markup
    assert 'href="/portal"' in markup


def test_an_analyst_sees_scanning_but_not_administration() -> None:
    markup = page("Scan", "<p>x</p>", user=_user(UserRole.ANALYST))

    assert 'href="/analyst"' in markup
    assert 'href="/admin/settings"' not in markup


def test_a_super_admin_sees_the_administration_links() -> None:
    markup = page("Scan", "<p>x</p>", user=_user(UserRole.SUPER_ADMIN))

    assert 'href="/admin/settings"' in markup
    assert 'href="/admin/audit"' in markup


def test_only_one_page_shell_exists() -> None:
    """Two hand-maintained shells drifted apart; the duplication must not come back."""

    shells = [p.name for p in _APP.rglob("*.py") if "<!doctype html>" in p.read_text()]

    # The unauthenticated sign-in page is deliberately separate; it has no session to render.
    assert sorted(shells) == ["auth.py", "layout.py"], shells
