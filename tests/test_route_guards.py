"""Deny-by-default coverage for every non-public HTTP route."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from typing import Any

from fastapi.routing import APIRoute

from app.config import Settings
from app.main import create_app

PUBLIC_PATHS = {
    "/",
    "/auth/csrf",
    "/auth/google/login",
    "/auth/google/callback",
    "/auth/local/login",
    # The organisation logo is rendered on the unauthenticated sign-in page.
    "/branding/logo",
    "/healthz",
}


def _walk_routes(router: Any) -> Iterator[object]:
    for route in router.routes:
        child = getattr(route, "original_router", None)
        if child is not None:
            yield from _walk_routes(child)
        else:
            yield route


def _has_role_guard(route: APIRoute) -> bool:
    return any(
        bool(getattr(dependency.call, "__leakcheck_role_guard__", False))
        for dependency in route.dependant.dependencies
    )


def test_every_non_public_route_has_an_explicit_role_guard() -> None:
    settings = Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )
    routes = list(_walk_routes(create_app(settings).router))
    unguarded = [
        route.path
        for route in routes
        if isinstance(route, APIRoute)
        and route.path not in PUBLIC_PATHS
        and not _has_role_guard(route)
    ]

    assert unguarded == []


def test_the_landing_page_leads_with_google_and_hides_the_password_form() -> None:
    """The portal is Google-first; the local form is break-glass access, not the default path."""

    import asyncio
    from unittest.mock import AsyncMock

    from app import branding
    from app.routers.auth import landing_page

    session_manager = AsyncMock()
    session_manager.verify = AsyncMock(return_value=None)
    request = type("R", (), {"cookies": {}})()

    async def run() -> str:
        original = branding.load
        branding.load = AsyncMock(  # type: ignore[assignment]
            return_value=branding.OrganisationBranding(
                name="CIA FIRST", has_logo=True, logo_sha256="abc"
            )
        )
        try:
            response = await landing_page(request, db=AsyncMock(), session_manager=session_manager)
        finally:
            branding.load = original  # type: ignore[assignment]
        return response.body.decode()

    markup = asyncio.run(run())

    assert "Sign in with Google to scan your email for leaked credentials." in markup
    assert 'href="/auth/google/login"' in markup
    assert "CIA FIRST" in markup
    assert '<img class="org-logo"' in markup
    # The password form exists but only inside a dialog behind the corner control.
    assert 'id="admin-toggle"' in markup
    assert "<dialog" in markup
    assert markup.index("google-button") < markup.index('id="local-login"')
