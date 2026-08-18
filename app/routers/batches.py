"""Analyst-only durable batch creation and progress routes."""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth.authorization import require_role
from app.batch_ui import batch_builder_page, batch_progress_fragment, batch_progress_page
from app.batches import create_batch
from app.db import get_db_session
from app.models import BatchTarget, ScanBatch, User, UserRole

_GUARD = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
router = APIRouter(
    prefix="/analyst/batches", dependencies=[Depends(_GUARD)], include_in_schema=False
)


@router.get("", response_model=None)
async def list_batches(
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    result = await db.execute(select(ScanBatch).order_by(ScanBatch.created_at.desc()).limit(50))
    batches = tuple(result.scalars())
    return _html(batch_builder_page(current_user, batches))


@router.post("", response_model=None)
async def add_batch(
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    body = await request.body()
    if len(body) > 12 * 1024:
        raise HTTPException(status_code=413, detail="Batch form is too large.")
    form = parse_qs(body.decode("utf-8", errors="strict"), keep_blank_values=True)
    try:
        target_type = BatchTarget(form.get("target_type", [""])[0])
        raw_target = form.get("target", [""])[0].strip()
        if target_type is BatchTarget.SELECTION:
            target: str | tuple[uuid.UUID, ...] = tuple(
                uuid.UUID(item.strip()) for item in raw_target.split(",") if item.strip()
            )
        else:
            target = raw_target
        if not target:
            raise ValueError
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Invalid batch target.") from exc
    try:
        batch = await create_batch(
            db, actor_id=current_user.id, target_type=target_type, target_value=target
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail="Batch target matched no active users."
        ) from exc
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="batch.created",
        actor_id=current_user.id,
        target_type="scan_batch",
        target_id=str(batch.id),
        meta={"target_type": target_type.value, "total_count": batch.total_count},
    )
    await db.commit()
    return RedirectResponse(f"/analyst/batches/{batch.id}", status_code=303)


@router.get("/{batch_id}", response_model=None)
async def batch_progress(
    batch_id: uuid.UUID,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    return _html(batch_progress_page(current_user, await _batch(db, batch_id)))


@router.get("/{batch_id}/status", response_model=None)
async def batch_status(
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    return _html(batch_progress_fragment(await _batch(db, batch_id)))


async def _batch(db: AsyncSession, batch_id: uuid.UUID) -> ScanBatch:
    result = await db.execute(select(ScanBatch).where(ScanBatch.id == batch_id))
    batch = result.scalar_one_or_none()
    if batch is None:
        raise HTTPException(status_code=404, detail="Batch not found.")
    return batch


def _html(body: str) -> HTMLResponse:
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})
