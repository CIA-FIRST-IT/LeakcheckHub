"""Escaped server-rendered HTML for the analyst workflow."""

from __future__ import annotations

import html
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Final

from app.models import FindingEventType, Scan, ScanStatus, Subject, SubjectKind, User, UserRole

_KINDS: Final = (
    SubjectKind.DOMAIN,
    SubjectKind.EMAIL,
    SubjectKind.PASSWORD,
    SubjectKind.USERNAME,
    SubjectKind.ORIGIN,
    SubjectKind.PHONE,
)


@dataclass(frozen=True, slots=True)
class FindingView:
    id: uuid.UUID
    source: str
    breach_date: date | None
    breach_date_text: str | None
    collected_date: date | None
    fields: tuple[str, ...]
    email: str | None
    username: str | None
    phone: str | None
    origin: str | None
    url: str | None
    password_mask: str | None
    has_password: bool
    remediated_at: datetime | None
    re_leaked: bool
    first_seen_at: datetime
    last_seen_at: datetime
    raw: dict[str, object]


@dataclass(frozen=True, slots=True)
class EventView:
    event: FindingEventType
    at: datetime
    actor: str | None
    meta: dict[str, object]


def analyst_dashboard(user: User, recent_subjects: tuple[Subject, ...]) -> str:
    cards = "".join(_check_card(kind) for kind in _KINDS)
    recent = (
        "".join(
            '<li><a href="/analyst/subjects/'
            + str(subject.id)
            + '"><span class="kind">'
            + _h(subject.kind.value)
            + "</span> "
            + _h(subject.value_display)
            + "</a></li>"
            for subject in recent_subjects
        )
        or '<li class="empty">No scans have been run yet.</li>'
    )
    content = "".join(
        (
            '<section class="hero"><p class="eyebrow">Exposure intelligence</p>',
            "<h1>Run a controlled check</h1>",
            "<p>Choose an identifier type. Queries are normalized before scanning, and searched ",
            "passwords are never stored in cleartext.</p></section>",
            '<section class="check-grid" aria-label="Leak checks">',
            cards,
            "</section>",
            '<section class="panel recent"><div class="section-heading"><div>',
            '<p class="eyebrow">Investigation trail</p><h2>Recent subjects</h2></div></div>',
            f'<ul class="recent-list">{recent}</ul></section>',
        )
    )
    return page("Analyst checks", content, user=user)


def scan_progress_page(user: User, scan: Scan, subject: Subject) -> str:
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Scan in progress</p><h1>',
            _h(subject.value_display),
            "</h1><p>Large lookups can take up to two minutes. This page updates without ",
            "holding the original request open.</p></section>",
            '<section class="panel" aria-live="polite">',
            scan_status_fragment(scan),
            "</section>",
        )
    )
    return page("Scan progress", content, user=user)


def scan_status_fragment(scan: Scan) -> str:
    if scan.status is ScanStatus.SUCCEEDED:
        return '<p class="scan-state success-text">Complete. Loading findings…</p>'
    if scan.status is ScanStatus.FAILED:
        return "".join(
            (
                '<div class="scan-state"><span class="badge danger">Failed</span>',
                "<h2>The check could not be completed</h2>",
                "<p>No query value or vendor response was retained. Return to checks and ",
                "try again.</p>",
                '<a class="button secondary" href="/analyst">Back to checks</a></div>',
            )
        )
    label = "Running" if scan.status is ScanStatus.RUNNING else "Queued"
    return "".join(
        (
            f'<div class="scan-state" hx-get="/analyst/scans/{scan.id}/status" ',
            'hx-trigger="load delay:1s" hx-swap="outerHTML">',
            '<span class="pulse" aria-hidden="true"></span>',
            f"<h2>{_h(label)} controlled check</h2>",
            "<p>Waiting for the bounded LeakCheck request and local ingest to finish…</p></div>",
        )
    )


def subject_history_page(
    user: User,
    subject: Subject,
    findings: tuple[FindingView, ...],
    events: tuple[EventView, ...],
    *,
    state: str = "all",
    source: str = "",
    date_from: str = "",
    date_to: str = "",
) -> str:
    filter_form = "".join(
        (
            '<form class="filters" method="get">',
            '<label>State<select name="state">',
            _option("all", "All", state),
            _option("unremediated", "Unremediated", state),
            _option("remediated", "Remediated", state),
            _option("releaked", "Re-leaked", state),
            "</select></label>",
            '<label>Search raw values<input type="search" id="result-search" name="source" value="',
            _h(source),
            '" maxlength="1024" placeholder="Email, origin, date, source…"></label>',
            '<label>From<input type="date" name="date_from" value="',
            _h(date_from),
            '"></label><label>To<input type="date" name="date_to" value="',
            _h(date_to),
            '"></label><button type="submit">Apply filters</button>',
            '<a class="button secondary" href="',
            _export_url(subject.id, state, source, date_from, date_to),
            '">Export CSV</a></form>',
        )
    )
    rows = "".join(finding_row(item) for item in findings)
    if not rows:
        rows = '<tr><td colspan="11" class="empty">No findings match these filters.</td></tr>'
    event_items = "".join(_event_item(event) for event in events)
    if not event_items:
        event_items = '<li class="empty">No recorded finding events.</li>'
    content = "".join(
        (
            '<header class="subject-header"><div><p class="eyebrow">',
            _h(subject.kind.value),
            " investigation</p><h1>",
            _h(subject.value_display),
            '</h1></div><a class="button secondary" href="/analyst">New check</a></header>',
            '<section class="panel"><div class="section-heading"><div><p class="eyebrow">',
            'Evidence</p><h2>Findings</h2></div><span class="count" id="findings-count" ',
            'data-total="',
            str(len(findings)),
            '">',
            str(len(findings)),
            " shown</span></div>",
            filter_form,
            '<div class="table-tools"><div class="table-config"><label>Rows per page',
            '<select id="findings-page-size">',
            '<option value="10" selected>10</option><option value="20">20</option>',
            '<option value="50">50</option><option value="100">100</option>',
            '<option value="all">All</option></select></label>',
            _column_picker(),
            '</div><div class="pagination">',
            '<button type="button" id="findings-prev" class="button secondary">Previous</button>',
            '<span id="findings-page-status">Page 1 of 1</span>',
            '<button type="button" id="findings-next" class="button secondary">Next</button>',
            '</div></div><div class="table-wrap"><table id="findings-table" ',
            'class="resizable-table"><colgroup>',
            '<col style="width:11rem"><col style="width:8rem"><col style="width:8rem">',
            '<col style="width:18rem"><col style="width:15rem"><col style="width:12rem">',
            '<col style="width:18rem"><col style="width:12rem"><col style="width:14rem">',
            '<col style="width:10rem"><col style="width:7rem"></colgroup><thead><tr>',
            _sort_header("Source", 0, "text"),
            _sort_header("Breached", 1, "date"),
            _sort_header("Collected", 2, "date"),
            _sort_header("Identity", 3, "text"),
            _sort_header("Fields", 4, "text"),
            _sort_header("Origin", 5, "text"),
            _sort_header("URL", 6, "text"),
            _sort_header("Password", 7, "text"),
            _sort_header("First / last seen", 8, "date"),
            _sort_header("Status", 9, "text"),
            '<th>Actions<span class="column-resizer" data-resize-handle aria-hidden="true"></span>',
            "</th></tr></thead><tbody data-findings-body>",
            rows,
            "</tbody></table></div></section>",
            '<section id="events" class="panel timeline"><div class="section-heading"><div>',
            '<p class="eyebrow">Immutable history</p><h2>Event trail</h2></div></div>',
            f'<ol class="event-list">{event_items}</ol></section>',
        )
    )
    return page(f"History · {subject.value_display}", content, user=user)


def finding_row(item: FindingView) -> str:
    row_class = "releaked" if item.re_leaked else ""
    badge = '<span class="badge danger">Re-leaked</span>' if item.re_leaked else ""
    identity = (
        "<br>".join(
            _identity_value(label, value, copy=label == "Email")
            for label, value in (
                ("Email", item.email),
                ("User", item.username),
                ("Phone", item.phone),
            )
            if value is not None
        )
        or "—"
    )
    fields = ", ".join(_h(field) for field in item.fields) or "—"
    raw = _h(json.dumps(item.raw, ensure_ascii=False, sort_keys=True, default=str))
    search_values = _h(_raw_value_text(item.raw).casefold())
    password = _h(item.password_mask) if item.password_mask is not None else "—"
    if item.has_password:
        password += (
            f'<div id="password-{item.id}" class="password-slot">'
            '<button type="button" class="link-button" '
            f'hx-post="/analyst/findings/{item.id}/reveal" '
            f'hx-target="#password-{item.id}" hx-swap="innerHTML">Reveal once</button></div>'
        )
    return "".join(
        (
            f'<tr class="{row_class}" data-search-values="{search_values}">',
            f'<td data-sort-value="{_h(item.source.casefold())}"><strong>',
            f"{_h(item.source)}</strong>{badge}</td>",
            _breach_date_cell(item),
            _date_cell(item.collected_date),
            f'<td data-sort-value="{_h(_identity_sort(item))}">{identity}</td>',
            f'<td data-sort-value="{_h(", ".join(item.fields).casefold())}">{fields}',
            f"<details><summary>Raw fields</summary><pre>{raw}</pre></details></td>",
            f'<td data-sort-value="{_h((item.origin or "").casefold())}">',
            f"{_h(item.origin) if item.origin else '—'}</td>",
            f'<td data-sort-value="{_h((item.url or "").casefold())}">',
            f"{_copy_value(item.url, 'URL') if item.url else '—'}</td>",
            f'<td class="password-cell" data-sort-value="{_h(item.password_mask or "")}">',
            f"{password}</td>",
            f'<td data-sort-value="{item.first_seen_at.timestamp()}">',
            f'<span class="seen-label">First</span> {_dt(item.first_seen_at)}<br>',
            f'<span class="seen-label">Last</span> {_dt(item.last_seen_at)}</td>',
            f'<td class="status-cell" data-sort-value="{_status_sort(item)}">',
            f'{remediation_control(item)}</td><td><a href="#events">Event trail</a></td></tr>',
        )
    )


def remediation_control(item: FindingView) -> str:
    return remediation_markup(item.id, remediated=item.remediated_at is not None)


def _sort_header(label: str, column: int, kind: str) -> str:
    return (
        f'<th><button type="button" class="sort-button" data-sort-column="{column}" '
        f'data-sort-kind="{_h(kind)}">{_h(label)} <span aria-hidden="true">↕</span></button>'
        '<span class="column-resizer" data-resize-handle aria-hidden="true"></span></th>'
    )


def _column_picker() -> str:
    labels = (
        "Source",
        "Breached",
        "Collected",
        "Identity",
        "Fields",
        "Origin",
        "URL",
        "Password",
        "First / last seen",
        "Status",
        "Actions",
    )
    controls = "".join(
        f'<label><input type="checkbox" value="{index}" data-column-toggle checked> '
        f"{_h(label)}</label>"
        for index, label in enumerate(labels)
    )
    return (
        '<details class="column-picker"><summary class="button secondary">Columns</summary>'
        f"<fieldset><legend>Show columns</legend>{controls}</fieldset></details>"
    )


def _identity_value(label: str, value: str, *, copy: bool) -> str:
    rendered = _copy_value(value, label) if copy else _h(value)
    return f"<span><strong>{_h(label)}</strong> {rendered}</span>"


def _copy_value(value: str, label: str) -> str:
    escaped = _h(value)
    return (
        f'<button type="button" class="copy-value" data-copy-value="{escaped}" '
        f'title="Copy {label.casefold()}">{escaped}</button>'
    )


def _identity_sort(item: FindingView) -> str:
    return " ".join(value for value in (item.email, item.username, item.phone) if value).casefold()


def _date_cell(value: date | None) -> str:
    sort_value = value.isoformat() if value is not None else ""
    display = value.strftime("%d-%m-%Y") if value is not None else "Unknown"
    return f'<td data-sort-value="{sort_value}">{display}</td>'


def _breach_date_cell(item: FindingView) -> str:
    if item.breach_date is not None:
        return _date_cell(item.breach_date)
    value = item.breach_date_text
    if value is None:
        return _date_cell(None)
    parts = value.split("-")
    if len(parts) == 2:
        display = f"{parts[1]}-{parts[0]}"
    else:
        display = value
    return f'<td data-sort-value="{_h(value)}">{_h(display)}</td>'


def _status_sort(item: FindingView) -> str:
    if item.re_leaked:
        return "re-leaked"
    return "remediated" if item.remediated_at is not None else "open"


def _raw_value_text(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(_raw_value_text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_raw_value_text(item) for item in value)
    if value is None:
        return ""
    return str(value)


def remediation_markup(finding_id: uuid.UUID, *, remediated: bool) -> str:
    if remediated:
        return "".join(
            (
                '<div class="remediation-control"><span class="badge success">Remediated</span>',
                '<button type="button" class="link-button" '
                f'hx-post="/analyst/findings/{finding_id}/unremediate" ',
                'hx-target="closest .remediation-control" hx-swap="outerHTML">',
                "Reopen</button></div>",
            )
        )
    return "".join(
        (
            '<div class="remediation-control"><span class="badge warning">Open</span>',
            '<button type="button" class="link-button" '
            f'hx-post="/analyst/findings/{finding_id}/remediate" ',
            'hx-target="closest .remediation-control" hx-swap="outerHTML">',
            "Mark remediated</button></div>",
        )
    )


def page(
    title: str,
    content: str,
    *,
    user: User,
    extra_styles: tuple[str, ...] = (),
    extra_scripts: tuple[str, ...] = (),
) -> str:
    admin_links = ""
    if user.role is UserRole.SUPER_ADMIN:
        admin_links = (
            '<a href="/admin/settings">Settings</a>'
            '<a href="/admin/audit">Audit</a>'
            '<a href="/account/profile">Profile</a>'
        )
    styles = "".join(f'<link rel="stylesheet" href="{_h(path)}">' for path in extra_styles)
    scripts = "".join(f'<script src="{_h(path)}" defer></script>' for path in extra_scripts)
    return "".join(
        (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<meta name="htmx-config" content=\'',
            '{"includeIndicatorStyles":false,"allowEval":false,"allowScriptTags":false}',
            "'>",
            f"<title>{_h(title)} · LeakCheck Hub</title>",
            '<link rel="stylesheet" href="/static/analyst.css?v=7">',
            styles,
            '<script src="/static/htmx-2.0.10.min.js" defer></script>',
            '<script src="/static/analyst.js?v=6" defer></script>',
            scripts,
            "</head><body>",
            '<header class="topbar"><a class="brand" href="/analyst">',
            '<span class="brand-mark" aria-hidden="true">L</span><span>LeakCheck Hub</span></a>',
            '<nav aria-label="Primary"><a href="/analyst">Scan</a>',
            admin_links,
            '<a href="/analyst/schedules">Schedule</a>',
            '</nav><div class="user-chip"><span>',
            _h(user.email),
            "</span><small>",
            _h(user.role.value.replace("_", " ")),
            "</small></div></header><main>",
            content,
            "</main><footer>Controlled exposure intelligence · ",
            "Cleartext credentials are reveal-only</footer>",
            "</body></html>",
        )
    )


def _check_card(kind: SubjectKind) -> str:
    descriptions = {
        SubjectKind.DOMAIN: "Review exposure across a company domain.",
        SubjectKind.EMAIL: "Investigate one exact mailbox identity.",
        SubjectKind.PASSWORD: (
            "Search a credential without storing the query. The cleartext is sent to LeakCheck; "
            "use their phash workflow instead when you already have a hash."
        ),
        SubjectKind.USERNAME: "Find reused handles across breach sources.",
        SubjectKind.ORIGIN: "Trace records associated with a service origin.",
        SubjectKind.PHONE: "Check an international E.164 telephone number.",
    }
    input_type = "password" if kind is SubjectKind.PASSWORD else "text"
    autocomplete = "new-password" if kind is SubjectKind.PASSWORD else "off"
    placeholder = {
        SubjectKind.DOMAIN: "example.com",
        SubjectKind.EMAIL: "person@example.com",
        SubjectKind.PASSWORD: "Enter password",
        SubjectKind.USERNAME: "username",
        SubjectKind.ORIGIN: "https://service.example.com",
        SubjectKind.PHONE: "+85512345678",
    }[kind]
    label = kind.value.title()
    return "".join(
        (
            '<article class="check-card"><div><span class="kind">',
            _h(kind.value),
            f"</span><h2>{_h(label)}</h2><p>{_h(descriptions[kind])}</p></div>",
            f'<form action="/analyst/scans/{kind.value}" method="post" '
            f'hx-post="/analyst/scans/{kind.value}" hx-target="find .form-error" '
            'hx-swap="innerHTML" hx-indicator="closest article">',
            f'<label for="query-{kind.value}">{_h(label)} value</label>',
            f'<input id="query-{kind.value}" name="query" type="{input_type}" '
            f'placeholder="{_h(placeholder)}" autocomplete="{autocomplete}" '
            'required maxlength="4096">',
            '<button type="submit">Run check</button><span class="htmx-indicator">Checking…</span>',
            '<output class="form-error" aria-live="polite"></output></form></article>',
        )
    )


def _event_item(event: EventView) -> str:
    actor = f" by {_h(event.actor)}" if event.actor else ""
    meta = _h(json.dumps(event.meta, ensure_ascii=False, sort_keys=True, default=str))
    return "".join(
        (
            '<li><span class="event-dot" aria-hidden="true"></span><div>',
            f"<strong>{_h(event.event.value.replace('_', ' ').title())}</strong>{actor}",
            f"<time>{_dt(event.at)}</time>",
            f"<details><summary>Metadata</summary><pre>{meta}</pre></details></div></li>",
        )
    )


def _export_url(
    subject_id: uuid.UUID, state: str, source: str, date_from: str, date_to: str
) -> str:
    from urllib.parse import urlencode

    query = urlencode(
        {
            "state": state,
            "source": source,
            "date_from": date_from,
            "date_to": date_to,
        }
    )
    return _h(f"/analyst/subjects/{subject_id}/export.csv?{query}")


def _option(value: str, label: str, selected: str) -> str:
    marker = " selected" if value == selected else ""
    return f'<option value="{_h(value)}"{marker}>{_h(label)}</option>'


def _dt(value: datetime) -> str:
    return _h(value.astimezone(UTC).strftime("%d-%m-%Y %H:%M"))


def _h(value: object) -> str:
    return html.escape(str(value), quote=True)
