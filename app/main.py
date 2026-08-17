"""FastAPI application factory and process entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.auth.csrf import CSRFMiddleware, CSRFProtector
from app.auth.local import LocalAuthenticator
from app.auth.session import SessionManager
from app.config import Settings, get_settings
from app.middleware import SecurityHeadersMiddleware
from app.platform_settings import PlatformSettingsStore
from app.routers.admin import router as admin_router
from app.routers.analyst import router as analyst_router
from app.routers.auth import router as auth_router
from app.routers.findings import router as findings_router
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
    app.state.google_oidc = None
    app.state.leakcheck_client = None
    app.state.leakcheck_client_config_digest = None
    app.state.leakcheck_client_lock = anyio.Lock()
    app.state.platform_settings = PlatformSettingsStore(resolved_settings)
    app.state.local_authenticator = LocalAuthenticator(resolved_settings)
    app.state.session_manager = SessionManager(resolved_settings)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(resolved_settings.trusted_hosts))
    app.add_middleware(CSRFMiddleware, protector=app.state.csrf_protector)
    app.add_middleware(SecurityHeadersMiddleware, environment=resolved_settings.environment)
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(analyst_router)
    app.include_router(findings_router)
    app.include_router(health_router)
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    return app
