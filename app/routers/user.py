"""Own-account-only self-service findings and remediation portal."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth.authorization import require_role
from app.db import get_async_session_factory, get_db_session
from app.leakcheck import LeakCheckConfigurationError
from app.models import (
    BreachSource,
    Finding,
    FindingSeverity,
    Scan,
    ScanStatus,
    ScanTrigger,
    Subject,
    SubjectKind,
    User,
    UserRole,
)
from app.normalization import NormalizedSubject, normalize_subject
from app.platform_settings import PlatformSettingError, PlatformSettingsStore, SettingKey
from app.remediation import FindingNotFoundError, remediate_finding
from app.scan_runtime import actor_scan_lock, configured_client, execute_scan, resolve_subject
from app.user_ui import dashboard_page, progress_fragment, progress_page, remediation_complete
from app.user_views import UserFindingProjection, serialize_user_finding

_PORTAL_GUARD = require_role(UserRole.USER, UserRole.ANALYST, UserRole.SUPER_ADMIN)
_DEFAULT_COOLDOWN_SECONDS = 24 * 60 * 60
_MAX_COOLDOWN_SECONDS = 30 * 24 * 60 * 60

router = APIRouter(prefix="/portal", dependencies=[Depends(_PORTAL_GUARD)], include_in_schema=False)


@router.get("", response_model=None)
async def user_dashboard(
    request: Request,
    current_user: User = Depends(_PORTAL_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    normalized = _current_subject(current_user)
    findings = await _user_findings(db, normalized)
    cooldown = await _cooldown_seconds(request, db)
    active_scan = await _active_self_scan(db, current_user.id)
    latest_scan = await _latest_self_scan(db, current_user.id)
    can_check = (
        active_scan is None and cooldown_remaining(latest_scan, cooldown_seconds=cooldown) == 0
    )
    serialized = tuple(serialize_user_finding(item) for item in findings)
    return _html(dashboard_page(current_user, serialized, can_check=can_check))


@router.post("/check", response_model=None)
async def self_check(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(_PORTAL_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    """Check only the session identity; no request field or parameter selects the subject."""

    normalized = _current_subject(current_user)
    await db.execute(select(func.pg_advisory_xact_lock(actor_scan_lock(current_user.id))))
    active_scan = await _active_self_scan(db, current_user.id)
    latest_scan = await _latest_self_scan(db, current_user.id)
    cooldown = await _cooldown_seconds(request, db)
    remaining = cooldown_remaining(latest_scan, cooldown_seconds=cooldown)
    if active_scan is not None:
        return _html("Your existing self-check is still in progress.", status_code=409)
    if remaining > 0:
        return _html(
            "Your self-check is in cooldown. Existing findings remain available below.",
            status_code=429,
            headers={"Retry-After": str(remaining)},
        )
    subject = await resolve_subject(db, normalized, linked_user_id=current_user.id)
    try:
        client = await configured_client(request, db)
    except (PlatformSettingError, LeakCheckConfigurationError, ValueError) as exc:
        await audit_event(
            db,
            request,
            request.app.state.settings,
            action="self.scan_rejected",
            actor_id=current_user.id,
            target_type="user",
            target_id=str(current_user.id),
            meta={"reason": type(exc).__name__},
        )
        return _html("Self-check is not configured. Contact your security team.", status_code=503)
    scan = Scan(
        id=uuid.uuid4(),
        subject_id=subject.id,
        requested_by=current_user.id,
        trigger=ScanTrigger.SELF,
        status=ScanStatus.PENDING,
        result_count=0,
        new_count=0,
        truncated=False,
    )
    db.add(scan)
    await db.flush()
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="self.scan_requested",
        actor_id=current_user.id,
        target_type="scan",
        target_id=str(scan.id),
        meta={"kind": SubjectKind.EMAIL.value},
    )
    await db.commit()
    background_tasks.add_task(
        execute_scan,
        get_async_session_factory(),
        client,
        request.app.state.settings,
        scan.id,
        subject.id,
        current_user.email,
    )
    location = f"/portal/scans/{scan.id}"
    if request.headers.get("HX-Request") == "true":
        return _html("", headers={"HX-Redirect": location})
    return RedirectResponse(location, status_code=303, headers={"Cache-Control": "no-store"})


@router.get("/scans/{scan_id}", response_model=None)
async def self_scan_progress(
    scan_id: uuid.UUID,
    current_user: User = Depends(_PORTAL_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    scan = await _owned_scan_or_404(db, scan_id, current_user.id)
    if scan.status is ScanStatus.SUCCEEDED:
        return RedirectResponse("/portal", status_code=303, headers={"Cache-Control": "no-store"})
    return _html(progress_page(current_user, scan))


@router.get("/scans/{scan_id}/status", response_model=None)
async def self_scan_status(
    scan_id: uuid.UUID,
    current_user: User = Depends(_PORTAL_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    scan = await _owned_scan_or_404(db, scan_id, current_user.id)
    if scan.status is ScanStatus.SUCCEEDED:
        return _html("", headers={"HX-Redirect": "/portal"})
    return _html(progress_fragment(scan))


@router.post("/findings/{finding_id}/remediate", response_model=None)
async def self_remediate(
    finding_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_PORTAL_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    normalized = _current_subject(current_user)
    ownership = await db.execute(_owned_finding_statement(finding_id, normalized))
    if ownership.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    try:
        finding = await remediate_finding(
            db,
            finding_id=finding_id,
            actor_id=current_user.id,
            note="Marked fixed by the affected user",
        )
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Finding not found.") from exc
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="self.finding_remediated",
        actor_id=current_user.id,
        target_type="finding",
        target_id=str(finding.id),
    )
    return _html(remediation_complete(str(finding.id)))


async def _user_findings(
    db: AsyncSession, normalized: NormalizedSubject
) -> tuple[UserFindingProjection, ...]:
    result = await db.execute(_user_findings_statement(normalized))
    return tuple(
        UserFindingProjection(
            id=row[0],
            source=row[1],
            breach_date=row[2],
            fields=tuple(row[3]),
            origin=row[4],
            password_mask=row[5],
            remediated_at=row[6],
            re_leaked=row[7] is FindingSeverity.HIGH,
            first_seen_at=row[8],
            last_seen_at=row[9],
        )
        for row in result.all()
    )


def _user_findings_statement(normalized: NormalizedSubject) -> Select[Any]:
    return (
        select(
            Finding.id,
            BreachSource.name,
            BreachSource.breach_date,
            Finding.fields,
            Finding.origin,
            Finding.password_mask,
            Finding.remediated_at,
            Finding.severity,
            Finding.first_seen_at,
            Finding.last_seen_at,
        )
        .join(Subject, Subject.id == Finding.subject_id)
        .join(BreachSource, BreachSource.id == Finding.source_id)
        .where(
            Subject.kind == SubjectKind.EMAIL,
            Subject.value_norm == normalized.value_norm,
        )
        .order_by(Finding.first_seen_at.desc())
        .limit(1000)
    )


def _owned_finding_statement(
    finding_id: uuid.UUID, normalized: NormalizedSubject
) -> Select[tuple[uuid.UUID]]:
    return (
        select(Finding.id)
        .join(Subject, Subject.id == Finding.subject_id)
        .where(
            Finding.id == finding_id,
            Subject.kind == SubjectKind.EMAIL,
            Subject.value_norm == normalized.value_norm,
        )
        .with_for_update()
    )


async def _latest_self_scan(db: AsyncSession, user_id: uuid.UUID) -> Scan | None:
    result = await db.execute(
        select(Scan)
        .where(
            Scan.requested_by == user_id,
            Scan.trigger == ScanTrigger.SELF,
            Scan.started_at.is_not(None),
        )
        .order_by(Scan.started_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _active_self_scan(db: AsyncSession, user_id: uuid.UUID) -> Scan | None:
    result = await db.execute(
        select(Scan)
        .where(
            Scan.requested_by == user_id,
            Scan.trigger == ScanTrigger.SELF,
            Scan.status.in_((ScanStatus.PENDING, ScanStatus.RUNNING)),
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _owned_scan_or_404(db: AsyncSession, scan_id: uuid.UUID, user_id: uuid.UUID) -> Scan:
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.requested_by == user_id,
            Scan.trigger == ScanTrigger.SELF,
        )
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


async def _cooldown_seconds(request: Request, db: AsyncSession) -> int:
    store = cast(PlatformSettingsStore, request.app.state.platform_settings)
    raw = await store.read(db, SettingKey.SELF_CHECK_COOLDOWN_SECONDS)
    try:
        value = _DEFAULT_COOLDOWN_SECONDS if raw is None else int(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=503, detail="Self-check cooldown is misconfigured."
        ) from exc
    if not 60 <= value <= _MAX_COOLDOWN_SECONDS:
        raise HTTPException(status_code=503, detail="Self-check cooldown is misconfigured.")
    return value


def cooldown_remaining(
    scan: Scan | None, *, cooldown_seconds: int, now: datetime | None = None
) -> int:
    if scan is None or scan.started_at is None:
        return 0
    current = (now or datetime.now(UTC)).astimezone(UTC)
    started = scan.started_at.astimezone(UTC)
    elapsed = max(0, int((current - started).total_seconds()))
    return max(0, cooldown_seconds - elapsed)


def _current_subject(user: User) -> NormalizedSubject:
    return normalize_subject(SubjectKind.EMAIL, user.email)


def _html(
    body: str, *, status_code: int = 200, headers: dict[str, str] | None = None
) -> HTMLResponse:
    return HTMLResponse(
        body,
        status_code=status_code,
        headers={"Cache-Control": "no-store", **(headers or {})},
    )
