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
