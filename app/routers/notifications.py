"""Analyst notification preview and explicit-confirm queueing."""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth.authorization import require_role
from app.db import get_db_session
from app.models import Finding, Notification, Subject, User, UserRole
from app.notification_ui import confirmation_page, notifications_page
from app.notifications import enqueue_notification

_GUARD = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
_TARGET_TYPES = frozenset({"user", "ou", "domain", "selection"})
router = APIRouter(
    prefix="/analyst/notifications", dependencies=[Depends(_GUARD)], include_in_schema=False
)


@router.get("", response_model=None)
async def list_notifications(
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    result = await db.execute(
        select(Notification).order_by(Notification.created_at.desc()).limit(100)
    )
    return _html(notifications_page(current_user, tuple(result.scalars())))


@router.post("/preview", response_model=None)
async def preview_notifications(
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    target_type, target = await _target_form(request)
    recipients = await _recipient_findings(db, target_type, target)
    return _html(confirmation_page(current_user, target_type, target, len(recipients)))


@router.post("/confirm", response_model=None)
async def confirm_notifications(
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    target_type, target = await _target_form(request)
    recipients = await _recipient_findings(db, target_type, target)
    for user_id, finding_ids in recipients.items():
        await enqueue_notification(db, user_id=user_id, finding_ids=tuple(finding_ids))
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="notifications.campaign_queued",
        actor_id=current_user.id,
        target_type="notification_campaign",
        meta={"target_type": target_type, "recipient_count": len(recipients)},
    )
    return RedirectResponse("/analyst/notifications", status_code=303)


async def _recipient_findings(
    db: AsyncSession, target_type: str, target: str
) -> dict[uuid.UUID, list[uuid.UUID]]:
    users = select(User.id).where(User.is_active.is_(True))
    if target_type == "user":
        users = users.where(User.email == target.casefold())
    elif target_type == "ou":
        escaped = _escape_like(target.rstrip("/") + "/") + "%"
        users = users.where(or_(User.ou_path == target, User.ou_path.like(escaped, escape="\\")))
    elif target_type == "domain":
        domain = _escape_like(target.casefold().lstrip("@"))
        users = users.where(User.email.ilike(f"%@{domain}", escape="\\"))
    else:
        try:
            ids = tuple(uuid.UUID(item.strip()) for item in target.split(",") if item.strip())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid user selection.") from exc
        users = users.where(User.id.in_(ids))
    rows = await db.execute(
        select(User.id, Finding.id)
        .join(Subject, Subject.linked_user_id == User.id)
        .join(Finding, Finding.subject_id == Subject.id)
        .where(User.id.in_(users), Finding.remediated_at.is_(None))
        .order_by(User.id, Finding.id)
    )
    grouped: dict[uuid.UUID, list[uuid.UUID]] = {}
    for user_id, finding_id in rows.all():
        grouped.setdefault(user_id, []).append(finding_id)
    return grouped


async def _target_form(request: Request) -> tuple[str, str]:
    body = await request.body()
    if len(body) > 12 * 1024:
        raise HTTPException(status_code=413, detail="Notification form is too large.")
    try:
        form = parse_qs(body.decode("utf-8", errors="strict"), keep_blank_values=True)
        target_type = form.get("target_type", [""])[0]
        target = form.get("target", [""])[0].strip()
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid notification target.") from exc
    if target_type not in _TARGET_TYPES or not target:
        raise HTTPException(status_code=422, detail="Invalid notification target.")
    return target_type, target


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _html(body: str, *, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(body, status_code=status_code, headers={"Cache-Control": "no-store"})
