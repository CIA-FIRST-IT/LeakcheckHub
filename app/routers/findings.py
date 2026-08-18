"""Analyst remediation API for persisted findings."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth.authorization import require_role
from app.db import get_db_session
from app.models import User, UserRole
from app.remediation import FindingNotFoundError, remediate_finding, unremediate_finding

_ANALYST_GUARD = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
router = APIRouter(
    prefix="/api/findings", dependencies=[Depends(_ANALYST_GUARD)], include_in_schema=False
)


class RemediationRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


@router.post("/{finding_id}/remediate", response_model=None)
async def remediate(
    finding_id: uuid.UUID,
    payload: RemediationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
) -> JSONResponse:
    try:
        finding = await remediate_finding(
            db,
            finding_id=finding_id,
            actor_id=current_user.id,
            note=payload.note,
        )
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Finding not found.") from exc
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="finding.remediated",
        actor_id=current_user.id,
        target_type="finding",
        target_id=str(finding.id),
    )
    return JSONResponse({"id": str(finding.id), "state": "remediated"})


@router.post("/{finding_id}/unremediate", response_model=None)
async def unremediate(
    finding_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
) -> JSONResponse:
    try:
        finding = await unremediate_finding(
            db,
            finding_id=finding_id,
            actor_id=current_user.id,
        )
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Finding not found.") from exc
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="finding.unremediated",
        actor_id=current_user.id,
        target_type="finding",
        target_id=str(finding.id),
    )
    return JSONResponse({"id": str(finding.id), "state": "unremediated"})
