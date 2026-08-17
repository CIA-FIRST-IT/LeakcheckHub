"""Session-backed authentication and deny-by-default role dependencies."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.db import get_db_session
from app.models import User, UserRole


async def get_session_manager_for_request(request: Request) -> SessionManager:
    """Read the session manager configured for this application instance."""

    return cast(SessionManager, request.app.state.session_manager)


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    session_manager: SessionManager = Depends(get_session_manager_for_request),  # noqa: B008
) -> User:
    """Resolve the active server-side session or fail closed before a route can act."""

    verified = await session_manager.verify(db, token=request.cookies.get(SESSION_COOKIE_NAME))
    if verified is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Session"},
        )
    return verified.user


def require_role(*allowed_roles: UserRole) -> Callable[..., Awaitable[User]]:
    """Create a dependency that permits exactly the supplied roles and denies all others."""

    allowed = frozenset(allowed_roles)
    if not allowed:
        raise ValueError("require_role needs at least one permitted role")

    async def dependency(current_user: User = Depends(get_current_user)) -> User:  # noqa: B008
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role.",
            )
        return current_user

    dependency.__dict__["__leakcheck_role_guard__"] = True
    return dependency
