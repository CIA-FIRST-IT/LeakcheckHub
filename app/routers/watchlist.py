"""Audited analyst watchlist management."""

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
from app.models import Subject, User, UserRole, WatchlistEntry
from app.normalization import NormalizationError, normalize_email
from app.watchlist_ui import WatchlistView, watchlist_page

_GUARD = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
router = APIRouter(
    prefix="/analyst/watchlist", dependencies=[Depends(_GUARD)], include_in_schema=False
)
_CHANNELS = frozenset({"alert_soc", "alert_user", "alert_wazuh", "alert_iris", "enabled"})


@router.get("", response_model=None)
async def list_watchlist(
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    entries = tuple(
        (await db.execute(select(WatchlistEntry).order_by(WatchlistEntry.created_at))).scalars()
    )
    views: list[WatchlistView] = []
    for entry in entries:
        if entry.user_id is not None:
            target = await db.scalar(select(User.email).where(User.id == entry.user_id))
            label = str(target or entry.user_id)
        else:
            target = await db.scalar(
                select(Subject.value_display).where(Subject.id == entry.subject_id)
            )
            label = str(target or entry.subject_id)
        views.append(WatchlistView(entry, label))
    return _html(watchlist_page(current_user, tuple(views)))


@router.post("", response_model=None)
async def add_watchlist_entry(
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    form = await _form(request)
    target_type = form.get("target_type", "")
    target = form.get("target", "").strip()
    user_id: uuid.UUID | None = None
    subject_id: uuid.UUID | None = None
    if target_type == "user":
        try:
            email = normalize_email(target)
        except NormalizationError as exc:
            raise HTTPException(status_code=422, detail="Invalid user email.") from exc
        user_id = await db.scalar(select(User.id).where(User.email == email))
        if user_id is None:
            raise HTTPException(status_code=404, detail="User not found.")
    elif target_type == "subject":
        try:
            subject_id = uuid.UUID(target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid subject ID.") from exc
        if await db.scalar(select(Subject.id).where(Subject.id == subject_id)) is None:
            raise HTTPException(status_code=404, detail="Subject not found.")
    else:
        raise HTTPException(status_code=422, detail="Invalid watchlist target.")
    duplicate_clause = (
        WatchlistEntry.user_id == user_id
        if user_id is not None
        else WatchlistEntry.subject_id == subject_id
    )
    existing = await db.scalar(select(WatchlistEntry.id).where(duplicate_clause))
    if existing is not None:
        raise HTTPException(status_code=409, detail="Target is already watchlisted.")
    entry = WatchlistEntry(
        id=uuid.uuid4(),
        user_id=user_id,
        subject_id=subject_id,
        alert_soc="alert_soc" in form,
        alert_user="alert_user" in form,
        alert_wazuh="alert_wazuh" in form,
        alert_iris="alert_iris" in form,
        enabled=True,
        created_by=current_user.id,
    )
    db.add(entry)
    await db.flush()
    await _audit(request, db, current_user, entry.id, "watchlist.created")
    return RedirectResponse("/analyst/watchlist", status_code=303)


@router.post("/{entry_id}/delete", response_model=None)
async def remove_watchlist_entry(
    entry_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    exists = await db.scalar(select(WatchlistEntry.id).where(WatchlistEntry.id == entry_id))
    if exists is None:
        raise HTTPException(status_code=404, detail="Watchlist entry not found.")
    await _audit(request, db, current_user, entry_id, "watchlist.deleted")
    await db.execute(delete(WatchlistEntry).where(WatchlistEntry.id == entry_id))
    return RedirectResponse("/analyst/watchlist", status_code=303)


@router.post("/{entry_id}/toggle/{channel}", response_model=None)
async def toggle_watchlist_channel(
    entry_id: uuid.UUID,
    channel: str,
    request: Request,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    if channel not in _CHANNELS:
        raise HTTPException(status_code=404, detail="Watchlist channel not found.")
    result = await db.execute(
        select(WatchlistEntry).where(WatchlistEntry.id == entry_id).with_for_update()
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail="Watchlist entry not found.")
    setattr(entry, channel, not bool(getattr(entry, channel)))
    await _audit(request, db, current_user, entry.id, "watchlist.channel_toggled", channel=channel)
    return RedirectResponse("/analyst/watchlist", status_code=303)


async def _form(request: Request) -> dict[str, str]:
    body = await request.body()
    if len(body) > 8 * 1024:
        raise HTTPException(status_code=413, detail="Watchlist form is too large.")
    try:
        return {
            key: values[0]
            for key, values in parse_qs(
                body.decode("utf-8", errors="strict"), keep_blank_values=True
            ).items()
        }
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid watchlist form.") from exc


async def _audit(
    request: Request,
    db: AsyncSession,
    actor: User,
    entry_id: uuid.UUID,
    action: str,
    *,
    channel: str | None = None,
) -> None:
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action=action,
        actor_id=actor.id,
        target_type="watchlist",
        target_id=str(entry_id),
        meta={"channel": channel} if channel else {},
    )


def _html(body: str) -> HTMLResponse:
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})
