"""Super-admin audit-log viewer.

The audit trail is append-only and deliberately holds no secrets: addresses are stored only as a
keyed hash, so this screen can never disclose a client IP or a credential.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst_ui import page
from app.auth.authorization import require_role
from app.db import get_db_session
from app.models import AuditLog, User, UserRole

router = APIRouter(prefix="/admin", tags=["admin"])

_GUARD = require_role(UserRole.SUPER_ADMIN)
_PAGE_SIZE = 50
_MAX_PAGE = 1000


def _filtered(
    statement: Select[tuple[AuditLog, str]],
    *,
    action: str | None,
    actor: str | None,
    since: datetime | None,
    until: datetime | None,
) -> Select[tuple[AuditLog, str]]:
    if action:
        statement = statement.where(AuditLog.action.ilike(f"%{action}%"))
    if actor:
        statement = statement.where(User.email.ilike(f"%{actor}%"))
    if since is not None:
        statement = statement.where(AuditLog.at >= since)
    if until is not None:
        statement = statement.where(AuditLog.at <= until)
    return statement


def _rows(entries: list[tuple[AuditLog, str | None]]) -> str:
    if not entries:
        return '<tr><td colspan="5">No audit entries match these filters.</td></tr>'
    cells = []
    for entry, actor_email in entries:
        target = " ".join(part for part in (entry.target_type, entry.target_id) if part)
        cells.append(
            "<tr><td>"
            + html.escape(entry.at.isoformat(sep=" ", timespec="seconds"))
            + "</td><td>"
            + html.escape(actor_email or "system")
            + "</td><td>"
            + html.escape(entry.action)
            + "</td><td>"
            + html.escape(target or "-")
            + "</td><td><code>"
            + html.escape(_summarise(entry.meta))
            + "</code></td></tr>"
        )
    return "".join(cells)


def _summarise(meta: dict[str, object]) -> str:
    if not meta:
        return "-"
    rendered = ", ".join(f"{key}={meta[key]!r}" for key in sorted(meta))
    return rendered if len(rendered) <= 300 else rendered[:297] + "..."


@router.get("/audit", response_model=None)
async def audit_page(
    request: Request,
    action: Annotated[str | None, Query(max_length=128)] = None,
    actor: Annotated[str | None, Query(max_length=255)] = None,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    page_number: Annotated[int, Query(ge=1, le=_MAX_PAGE, alias="page")] = 1,
    current_user: User = Depends(_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    """List audit entries newest first, filtered by action, actor, and time window."""

    statement = _filtered(
        select(AuditLog, User.email).join(User, AuditLog.actor_id == User.id, isouter=True),
        action=action,
        actor=actor,
        since=since,
        until=until,
    )
    statement = (
        statement.order_by(AuditLog.at.desc())
        .offset((page_number - 1) * _PAGE_SIZE)
        .limit(_PAGE_SIZE + 1)
    )
    found = list((await db.execute(statement)).all())
    has_more = len(found) > _PAGE_SIZE
    entries = [(row[0], row[1]) for row in found[:_PAGE_SIZE]]

    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Administration</p>',
            "<h1>Audit log</h1><p>Every human action and authentication event, newest first. ",
            "Client addresses are stored only as a keyed hash and are never shown.</p></section>",
            '<form class="panel" method="get" action="/admin/audit">',
            '<label>Action <input name="action" value="',
            html.escape(action or ""),
            '"></label>',
            '<label>Actor email <input name="actor" value="',
            html.escape(actor or ""),
            '"></label>',
            '<label>From <input type="datetime-local" name="since" value="',
            html.escape(since.isoformat(timespec="minutes") if since else ""),
            '"></label>',
            '<label>To <input type="datetime-local" name="until" value="',
            html.escape(until.isoformat(timespec="minutes") if until else ""),
            '"></label>',
            '<button type="submit">Filter</button> ',
            '<a href="/admin/audit">Clear</a></form>',
            '<section class="panel"><div class="table-wrap"><table><thead><tr>',
            "<th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th>",
            "</tr></thead><tbody>",
            _rows(entries),
            "</tbody></table></div>",
            _pager(page_number, has_more=has_more, request=request),
            "</section>",
        )
    )
    body = page(
        "Audit log",
        content,
        user=current_user,
        extra_styles=("/static/admin-settings.css?v=5",),
    )
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


def _pager(page_number: int, *, has_more: bool, request: Request) -> str:
    def link(target: int, label: str) -> str:
        params = dict(request.query_params)
        params["page"] = str(target)
        query = "&".join(f"{html.escape(k)}={html.escape(v)}" for k, v in params.items())
        return f'<a href="/admin/audit?{query}">{label}</a>'

    parts = []
    if page_number > 1:
        parts.append(link(page_number - 1, "Previous"))
    parts.append(f"<span>Page {page_number}</span>")
    if has_more:
        parts.append(link(page_number + 1, "Next"))
    return '<p class="pager">' + " ".join(parts) + "</p>"


__all__ = ["router"]
