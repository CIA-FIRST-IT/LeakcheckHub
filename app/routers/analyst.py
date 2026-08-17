"""Role-bound analyst scan, findings, history, reveal, and export routes."""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import cast
from urllib.parse import parse_qs

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from app.analyst_ui import (
    EventView,
    FindingView,
    analyst_dashboard,
    remediation_markup,
    scan_progress_page,
    scan_status_fragment,
    subject_history_page,
)
from app.audit import audit_event
from app.auth.authorization import require_role
from app.db import get_async_session_factory, get_db_session
from app.finding_crypto import FindingCryptoError, reveal_password
from app.leakcheck import (
    LeakCheckConfigurationError,
)
from app.models import (
    BreachSource,
    Finding,
    FindingEvent,
    FindingEventType,
    FindingSeverity,
    Scan,
    ScanStatus,
    ScanTrigger,
    Subject,
    SubjectKind,
    User,
    UserRole,
)
from app.normalization import NormalizationError, normalize_subject
from app.platform_settings import PlatformSettingError
from app.remediation import FindingNotFoundError, remediate_finding, unremediate_finding
from app.scan_runtime import actor_scan_lock, configured_client, execute_scan, resolve_subject

_ANALYST_GUARD = require_role(UserRole.ANALYST, UserRole.SUPER_ADMIN)
_MAX_FORM_BYTES = 8 * 1024
_MAX_RESULTS = 2_000
router = APIRouter(
    prefix="/analyst", dependencies=[Depends(_ANALYST_GUARD)], include_in_schema=False
)


@dataclass(frozen=True, slots=True)
class FindingFilters:
    state: str = "all"
    source: str = ""
    date_from: date | None = None
    date_to: date | None = None

    @classmethod
    def from_request(cls, request: Request) -> FindingFilters:
        state = request.query_params.get("state", "all")
        if state not in {"all", "unremediated", "remediated", "releaked"}:
            raise HTTPException(status_code=422, detail="Invalid finding state filter.")
        source = request.query_params.get("source", "").strip()
        if len(source) > 1024 or any(not character.isprintable() for character in source):
            raise HTTPException(status_code=422, detail="Invalid source filter.")
        date_from = _parse_filter_date(request.query_params.get("date_from", ""))
        date_to = _parse_filter_date(request.query_params.get("date_to", ""))
        if date_from and date_to and date_from > date_to:
            raise HTTPException(
                status_code=422, detail="The start date must not follow the end date."
            )
        return cls(state=state, source=source, date_from=date_from, date_to=date_to)


@router.get("", response_model=None)
async def dashboard(
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    result = await db.execute(
        select(Subject).order_by(Subject.last_scanned_at.desc().nullslast()).limit(20)
    )
    body = analyst_dashboard(current_user, tuple(result.scalars()))
    return _html(body)


@router.post("/scans/{kind}", response_model=None)
async def run_analyst_scan(
    kind: SubjectKind,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    query = await _query_from_form(request)
    try:
        normalized = normalize_subject(kind, query)
    except NormalizationError as exc:
        return _html(str(exc), status_code=422)
    await db.execute(select(func.pg_advisory_xact_lock(actor_scan_lock(current_user.id))))
    active_result = await db.execute(
        select(Scan.id)
        .where(
            Scan.requested_by == current_user.id,
            Scan.status.in_((ScanStatus.PENDING, ScanStatus.RUNNING)),
        )
        .limit(1)
    )
    if active_result.scalar_one_or_none() is not None:
        return _html("You already have a check in progress.", status_code=409)
    subject = await resolve_subject(db, normalized)
    try:
        client = await configured_client(request, db)
    except (PlatformSettingError, LeakCheckConfigurationError, ValueError) as exc:
        await audit_event(
            db,
            request,
            request.app.state.settings,
            action="analyst.scan_rejected",
            actor_id=current_user.id,
            target_type="subject",
            target_id=str(subject.id),
            meta={"kind": kind.value, "reason": type(exc).__name__},
        )
        return _html(
            "LeakCheck is not configured. Ask a super-admin to review Platform settings.",
            status_code=503,
        )

    scan = Scan(
        id=uuid.uuid4(),
        subject_id=subject.id,
        requested_by=current_user.id,
        trigger=ScanTrigger.MANUAL,
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
        action="analyst.scan_requested",
        actor_id=current_user.id,
        target_type="scan",
        target_id=str(scan.id),
        meta={"kind": kind.value},
    )
    # Background work uses another transaction, so make the pending row visible before responding.
    await db.commit()
    background_tasks.add_task(
        execute_scan,
        get_async_session_factory(),
        client,
        request.app.state.settings,
        scan.id,
        subject.id,
        query,
    )
    location = f"/analyst/scans/{scan.id}"
    if request.headers.get("HX-Request") == "true":
        return _html("", headers={"HX-Redirect": location})
    return RedirectResponse(location, status_code=303, headers={"Cache-Control": "no-store"})


@router.get("/scans/{scan_id}", response_model=None)
async def scan_progress(
    scan_id: uuid.UUID,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    scan, subject = await _scan_or_404(db, scan_id)
    if scan.status is ScanStatus.SUCCEEDED:
        return RedirectResponse(
            f"/analyst/subjects/{subject.id}",
            status_code=303,
            headers={"Cache-Control": "no-store"},
        )
    return _html(scan_progress_page(current_user, scan, subject))


@router.get("/scans/{scan_id}/status", response_model=None)
async def scan_progress_status(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    scan, subject = await _scan_or_404(db, scan_id)
    if scan.status is ScanStatus.SUCCEEDED:
        return _html("", headers={"HX-Redirect": f"/analyst/subjects/{subject.id}"})
    return _html(scan_status_fragment(scan))


@router.get("/subjects/{subject_id}", response_model=None)
async def subject_history(
    subject_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    subject = await _subject_or_404(db, subject_id)
    filters = FindingFilters.from_request(request)
    findings = await _finding_views(db, subject_id, filters)
    events = await _event_views(db, subject_id)
    body = subject_history_page(
        current_user,
        subject,
        findings,
        events,
        state=filters.state,
        source=filters.source,
        date_from=filters.date_from.isoformat() if filters.date_from else "",
        date_to=filters.date_to.isoformat() if filters.date_to else "",
    )
    return _html(body)


@router.post("/findings/{finding_id}/reveal", response_model=None)
async def reveal_finding_password(
    finding_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    result = await db.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(undefer(Finding.password_ciphertext), undefer(Finding.password_nonce))
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if finding.password_ciphertext is None or finding.password_nonce is None:
        raise HTTPException(status_code=404, detail="This finding has no stored password.")
    try:
        password = reveal_password(
            request.app.state.settings,
            finding_id=finding.id,
            ciphertext=finding.password_ciphertext,
            nonce=finding.password_nonce,
        )
    except FindingCryptoError as exc:
        raise HTTPException(
            status_code=409, detail="The stored credential could not be authenticated."
        ) from exc
    db.add(
        FindingEvent(
            id=uuid.uuid4(),
            finding_id=finding.id,
            event=FindingEventType.PASSWORD_VIEWED,
            actor_id=current_user.id,
            at=datetime.now(UTC),
            meta={},
        )
    )
    await db.flush()
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="finding.password_viewed",
        actor_id=current_user.id,
        target_type="finding",
        target_id=str(finding.id),
    )
    from html import escape

    return _html(
        '<button type="button" class="revealed-password copy-value" data-copy-value="'
        + escape(password, quote=True)
        + '" title="Copy password">'
        + escape(password, quote=True)
        + "</button>",
        headers={"Pragma": "no-cache"},
    )


@router.post("/findings/{finding_id}/remediate", response_model=None)
async def mark_remediated(
    finding_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    try:
        finding = await remediate_finding(
            db, finding_id=finding_id, actor_id=current_user.id, note=None
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
    return _html(remediation_markup(finding.id, remediated=True))


@router.post("/findings/{finding_id}/unremediate", response_model=None)
async def mark_unremediated(
    finding_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> HTMLResponse:
    try:
        finding = await unremediate_finding(db, finding_id=finding_id, actor_id=current_user.id)
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
    return _html(remediation_markup(finding.id, remediated=False))


@router.get("/subjects/{subject_id}/export.csv", response_model=None)
async def export_subject_csv(
    subject_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_ANALYST_GUARD),  # noqa: B008
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> Response:
    subject = await _subject_or_404(db, subject_id)
    filters = FindingFilters.from_request(request)
    findings = await _finding_views(db, subject_id, filters)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(
        (
            "source",
            "breach_date",
            "collected_date",
            "email",
            "username",
            "phone",
            "origin",
            "fields",
            "password_mask",
            "state",
            "re_leaked",
            "first_seen_at",
            "last_seen_at",
        )
    )
    for item in findings:
        writer.writerow(
            tuple(
                _csv_cell(value)
                for value in (
                    item.source,
                    item.breach_date.isoformat() if item.breach_date else "",
                    item.collected_date.isoformat() if item.collected_date else "",
                    item.email or "",
                    item.username or "",
                    item.phone or "",
                    item.origin or "",
                    ", ".join(item.fields),
                    item.password_mask or "",
                    "remediated" if item.remediated_at else "unremediated",
                    str(item.re_leaked).lower(),
                    item.first_seen_at.isoformat(),
                    item.last_seen_at.isoformat(),
                )
            )
        )
    await audit_event(
        db,
        request,
        request.app.state.settings,
        action="findings.csv_exported",
        actor_id=current_user.id,
        target_type="subject",
        target_id=str(subject.id),
        meta={**_filter_meta(filters), "row_count": len(findings)},
    )
    return Response(
        output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                f'attachment; filename="leakcheck-{subject.kind.value}-findings.csv"'
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


async def _subject_or_404(db: AsyncSession, subject_id: uuid.UUID) -> Subject:
    result = await db.execute(select(Subject).where(Subject.id == subject_id))
    subject = result.scalar_one_or_none()
    if subject is None:
        raise HTTPException(status_code=404, detail="Subject not found.")
    return subject


async def _scan_or_404(db: AsyncSession, scan_id: uuid.UUID) -> tuple[Scan, Subject]:
    result = await db.execute(
        select(Scan, Subject).join(Subject, Subject.id == Scan.subject_id).where(Scan.id == scan_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return cast(Scan, row[0]), cast(Subject, row[1])


async def _finding_views(
    db: AsyncSession, subject_id: uuid.UUID, filters: FindingFilters
) -> tuple[FindingView, ...]:
    statement = (
        select(Finding, BreachSource)
        .join(BreachSource, BreachSource.id == Finding.source_id)
        .where(Finding.subject_id == subject_id)
    )
    statement = _apply_filters(statement, filters)
    result = await db.execute(
        statement.order_by(
            BreachSource.breach_date.desc().nullslast(), Finding.first_seen_at.desc()
        ).limit(_MAX_RESULTS)
    )
    views = tuple(
        FindingView(
            id=finding.id,
            source=source.name,
            breach_date=source.breach_date,
            collected_date=_raw_date(finding.raw.get("collected")),
            fields=tuple(finding.fields),
            email=finding.email,
            username=finding.username,
            phone=finding.phone,
            origin=finding.origin or _raw_origin(finding.raw.get("origin")),
            password_mask=finding.password_mask,
            has_password=finding.password_sha256 is not None,
            remediated_at=finding.remediated_at,
            re_leaked=finding.severity is FindingSeverity.HIGH,
            first_seen_at=finding.first_seen_at,
            last_seen_at=finding.last_seen_at,
            raw=finding.raw,
        )
        for finding, source in result.all()
    )
    if filters.source:
        needle = filters.source.casefold()
        views = tuple(item for item in views if needle in _raw_value_text(item.raw).casefold())
    return views


async def _event_views(db: AsyncSession, subject_id: uuid.UUID) -> tuple[EventView, ...]:
    result = await db.execute(
        select(FindingEvent, User.display_name)
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .outerjoin(User, User.id == FindingEvent.actor_id)
        .where(Finding.subject_id == subject_id)
        .order_by(FindingEvent.at.desc())
    )
    return tuple(
        EventView(event=event.event, at=event.at, actor=actor, meta=event.meta)
        for event, actor in result.all()
    )


def _apply_filters(
    statement: Select[tuple[Finding, BreachSource]], filters: FindingFilters
) -> Select[tuple[Finding, BreachSource]]:
    if filters.state == "unremediated":
        statement = statement.where(Finding.remediated_at.is_(None))
    elif filters.state == "remediated":
        statement = statement.where(Finding.remediated_at.is_not(None))
    elif filters.state == "releaked":
        statement = statement.where(Finding.severity == FindingSeverity.HIGH)
    if filters.date_from:
        statement = statement.where(BreachSource.breach_date >= filters.date_from)
    if filters.date_to:
        statement = statement.where(BreachSource.breach_date <= filters.date_to)
    return statement


def _raw_origin(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        origins = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
        return ", ".join(origins) or None
    return None


def _raw_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _raw_value_text(value: object) -> str:
    """Flatten only JSON leaf values for the analyst search index."""

    if isinstance(value, dict):
        return " ".join(_raw_value_text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_raw_value_text(item) for item in value)
    if value is None:
        return ""
    return str(value)


async def _query_from_form(request: Request) -> str:
    content_type = request.headers.get("content-type", "").split(";", maxsplit=1)[0].strip()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="Expected a form submission.")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_FORM_BYTES:
                raise HTTPException(status_code=413, detail="Form is too large.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length.") from exc
    body = await request.body()
    if len(body) > _MAX_FORM_BYTES:
        raise HTTPException(status_code=413, detail="Form is too large.")
    try:
        fields = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=2,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Invalid form submission.") from exc
    queries = fields.get("query", [])
    if len(queries) != 1:
        raise HTTPException(status_code=422, detail="Exactly one query value is required.")
    return queries[0]


def _parse_filter_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid date filter.") from exc


def _filter_meta(filters: FindingFilters) -> dict[str, object]:
    values = asdict(filters)
    return {
        key: value.isoformat() if isinstance(value, date) else value
        for key, value in values.items()
    }


def _csv_cell(value: str) -> str:
    # Prevent spreadsheet formula execution when an exported vendor value is opened interactively.
    if value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def _html(
    body: str, *, status_code: int = 200, headers: dict[str, str] | None = None
) -> HTMLResponse:
    response_headers = {"Cache-Control": "no-store", **(headers or {})}
    return HTMLResponse(body, status_code=status_code, headers=response_headers)
