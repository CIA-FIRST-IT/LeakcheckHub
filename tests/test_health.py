"""Tests for the hardened unauthenticated health endpoint."""

from __future__ import annotations

import base64

import httpx
import pytest

from app.config import Environment, Settings
from app.main import create_app


def make_settings(environment: Environment = Environment.DEVELOPMENT) -> Settings:
    return Settings(
        environment=environment,
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("portal.example.test",),
    )


@pytest.mark.anyio
async def test_health_endpoint_exposes_no_configuration() -> None:
    app = create_app(make_settings())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://portal.example.test"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "strict-transport-security" not in response.headers


@pytest.mark.anyio
async def test_production_health_response_includes_hsts() -> None:
    app = create_app(make_settings(Environment.PRODUCTION))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://portal.example.test"
    ) as client:
        response = await client.get("/healthz")

    assert response.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains"


@pytest.mark.anyio
async def test_unknown_hosts_are_rejected_before_route_handling() -> None:
    app = create_app(make_settings())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://untrusted.example.test"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 400
