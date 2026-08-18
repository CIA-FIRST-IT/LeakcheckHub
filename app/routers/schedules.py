"""Analyst schedule CRUD with audited human changes."""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth.authorization import require_role
from app.db import get_db_session
from app.models import Schedule, ScheduleKind, User, UserRole
from app.schedule_ui import preview_fragment, schedules_page
from app.scheduling import ScheduleValidationError, next_fire_time

_GUARD = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
router = APIRouter(
    prefix="/analyst/schedules", dependencies=[Depends(_GUARD)], include_in_schema=False
)


@router.get("", response_model=None)
async def list_schedules(
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    result = await db.execute(select(Schedule).order_by(Schedule.created_at.desc()))
    return _html(schedules_page(current_user, tuple(result.scalars())))


@router.get("/preview", response_model=None)
async def preview_schedule(request: Request) -> HTMLResponse:
    try:
        next_run = next_fire_time(
            request.query_params.get("cron", ""), request.query_params.get("timezone", "")
        )
    except ScheduleValidationError as exc:
        return _html(str(exc), status_code=422)
    return _html(preview_fragment(next_run))


@router.post("", response_model=None)
async def create_schedule(
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    form = await _form(request)
    try:
        kind = ScheduleKind(form["kind"])
        target = form["target"].strip()
        cron = form["cron"].strip()
        timezone = form["timezone"].strip()
        grace = int(form.get("misfire_grace_seconds", "300"))
        if not target or len(target) > 1024 or not 0 <= grace <= 86_400:
            raise ValueError
        next_run = next_fire_time(cron, timezone)
    except (KeyError, ValueError, ScheduleValidationError) as exc:
        raise HTTPException(status_code=422, detail="Invalid schedule.") from exc
    schedule = Schedule(
        id=uuid.uuid4(),
        kind=kind,
        target=target,
        cron=cron,
        timezone=timezone,
        enabled=True,
        misfire_grace_seconds=grace,
        next_run_at=next_run,
        created_by=current_user.id,
    )
    db.add(schedule)
    await db.flush()
    await _audit(request, db, current_user, schedule, "schedule.created")
    return RedirectResponse("/analyst/schedules", status_code=303)


@router.post("/{schedule_id}/toggle", response_model=None)
async def toggle_schedule(
    schedule_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    schedule = await _schedule(db, schedule_id)
    schedule.enabled = not schedule.enabled
    if schedule.enabled:
        schedule.next_run_at = next_fire_time(schedule.cron, schedule.timezone)
    await _audit(request, db, current_user, schedule, "schedule.toggled")
    return RedirectResponse("/analyst/schedules", status_code=303)


@router.post("/{schedule_id}/delete", response_model=None)
async def remove_schedule(
    schedule_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    schedule = await _schedule(db, schedule_id)
    await _audit(request, db, current_user, schedule, "schedule.deleted")
    await db.execute(delete(Schedule).where(Schedule.id == schedule.id))
    return RedirectResponse("/analyst/schedules", status_code=303)


async def _schedule(db: AsyncSession, schedule_id: uuid.UUID) -> Schedule:
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id).with_for_update())
    schedule = result.scalar_one_or_none()
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return schedule


async def _form(request: Request) -> dict[str, str]:
    body = await request.body()
    if len(body) > 8 * 1024:
        raise HTTPException(status_code=413, detail="Schedule form is too large.")
    try:
        return {
            key: values[0]
            for key, values in parse_qs(
                body.decode("utf-8", errors="strict"), keep_blank_values=True
            ).items()
        }
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid schedule form.") from exc


async def _audit(
    request: Request, db: AsyncSession, actor: User, schedule: Schedule, action: str
) -> None:
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action=action,
        actor_id=actor.id,
        target_type="schedule",
        target_id=str(schedule.id),
        meta={"kind": schedule.kind.value},
    )


def _html(body: str, *, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(body, status_code=status_code, headers={"Cache-Control": "no-store"})
