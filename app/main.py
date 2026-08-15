"""FastAPI application factory and process entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.auth.csrf import CSRFMiddleware, CSRFProtector
from app.auth.google import GoogleOIDC
from app.auth.local import LocalAuthenticator
from app.auth.session import SessionManager
from app.config import Settings, get_settings
from app.middleware import SecurityHeadersMiddleware
from app.routers.auth import router as auth_router
from app.routers.health import router as health_router


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the web application without creating database connections at import time."""

    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Settings have already been fully validated before a listener is exposed.
        yield

    app = FastAPI(
        title="LeakCheck SOC Portal",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.csrf_protector = CSRFProtector(resolved_settings)
    app.state.google_oidc = GoogleOIDC(resolved_settings)
    app.state.local_authenticator = LocalAuthenticator(resolved_settings)
    app.state.session_manager = SessionManager(resolved_settings)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(resolved_settings.trusted_hosts))
    app.add_middleware(CSRFMiddleware, protector=app.state.csrf_protector)
    app.add_middleware(SecurityHeadersMiddleware, environment=resolved_settings.environment)
    app.include_router(auth_router)
    app.include_router(health_router)
    return app
