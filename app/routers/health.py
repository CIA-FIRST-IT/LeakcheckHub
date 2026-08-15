"""Unauthenticated liveness endpoint for orchestrators."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Return no sensitive configuration or dependency details."""

    return {"status": "ok"}
