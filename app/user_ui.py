"""Escaped HTML for the own-account self-service portal."""

from __future__ import annotations

import html
from collections.abc import Mapping

from app.models import Scan, ScanStatus, User


def dashboard_page(user: User, findings: tuple[dict[str, object], ...], *, can_check: bool) -> str:
    cards = "".join(_finding_card(item) for item in findings)
    if not cards:
        cards = (
            '<section class="panel empty-state"><h2>No known exposures</h2>'
            "<p>Your portal has no stored findings for this email address.</p></section>"
        )
    button = (
        '<button type="submit">Scan now</button>'
        if can_check
        else '<button type="button" disabled>Scan available after cooldown</button>'
    )
    content = "".join(
        (
            '<section class="hero user-portal-hero"><p class="eyebrow">Signed in as</p><h1>',
            _h(user.email),
            "</h1><p>Results are limited to this email address. ",
            "Passwords are always masked here.</p>",
            '<form action="/portal/check" method="post" hx-post="/portal/check" ',
            'hx-target="#self-check-message" hx-swap="innerHTML">',
            button,
            '<output id="self-check-message" class="form-error" aria-live="polite"></output>',
            '</form></section><section class="user-findings">',
            cards,
            "</section>",
        )
    )
    return _page("My exposure dashboard", content, user)


def progress_page(user: User, scan: Scan) -> str:
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Private self-check</p>',
            "<h1>Checking your work email</h1><p>The submitted identifier came from your ",
            "signed-in ",
            "account and is not accepted from page parameters.</p></section>",
            '<section class="panel" aria-live="polite">',
            progress_fragment(scan),
            "</section>",
        )
    )
    return _page("Self-check progress", content, user)


def progress_fragment(scan: Scan) -> str:
    if scan.status is ScanStatus.SUCCEEDED:
        return '<p class="scan-state success-text">Complete. Loading your results…</p>'
    if scan.status is ScanStatus.FAILED:
        return "".join(
            (
                '<div class="scan-state"><span class="badge danger">Failed</span>',
                "<h2>The check could not be completed</h2>",
                "<p>No credential or vendor error detail was retained.</p>",
                '<a class="button secondary" href="/portal">Back to dashboard</a></div>',
            )
        )
    label = "Running" if scan.status is ScanStatus.RUNNING else "Queued"
    return "".join(
        (
            f'<div class="scan-state" hx-get="/portal/scans/{scan.id}/status" ',
            'hx-trigger="load delay:1s" hx-swap="outerHTML"><span class="pulse" ',
            'aria-hidden="true"></span>',
            f"<h2>{_h(label)} private check</h2>",
            "<p>This page will update when the bounded scan finishes.</p></div>",
        )
    )


def remediation_complete(finding_id: str) -> str:
    return (
        '<div class="remediation-control"><span class="badge success">Marked fixed</span>'
        f'<span class="sr-only">Finding {_h(finding_id)}</span></div>'
    )


def _finding_card(item: Mapping[str, object]) -> str:
    finding_id = _h(item["id"])
    state = (
        '<span class="badge success">Fixed</span>'
        if item["remediated"]
        else '<span class="badge warning">Action needed</span>'
    )
    releak = '<span class="badge danger">Re-leaked</span>' if item["re_leaked"] else ""
    action = ""
    if not item["remediated"]:
        action = "".join(
            (
                '<div class="remediation-control">',
                f'<button type="button" hx-post="/portal/findings/{finding_id}/remediate" ',
                'hx-target="closest .remediation-control" hx-swap="outerHTML">',
                "I have fixed this</button></div>",
            )
        )
    field_value = item["fields"]
    field_items = field_value if isinstance(field_value, list) else []
    fields = ", ".join(_h(value) for value in field_items) or "Not specified"
    return "".join(
        (
            '<article class="panel user-finding"><header><div><p class="eyebrow">',
            _h(item["breach_date"] or "Unknown date"),
            "</p><h2>",
            _h(item["source"]),
            "</h2></div><div>",
            state,
            releak,
            "</div></header><dl><div><dt>Exposed fields</dt><dd>",
            fields,
            "</dd></div><div><dt>Service origin</dt><dd>",
            _h(item["origin"] or "Not provided"),
            "</dd></div><div><dt>Password hint</dt><dd>",
            _h(item["password_mask"] or "No password in this record"),
            '</dd></div></dl><p class="guidance">',
            _h(item["guidance"]),
            "</p>",
            action,
            "</article>",
        )
    )


def _page(title: str, content: str, user: User) -> str:
    return "".join(
        (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<meta name="htmx-config" content=\'',
            '{"includeIndicatorStyles":false,"allowEval":false,"allowScriptTags":false}',
            "'>",
            f"<title>{_h(title)} · LeakCheck Hub</title>",
            '<link rel="stylesheet" href="/static/analyst.css?v=6">',
            '<script src="/static/htmx-2.0.10.min.js" defer></script>',
            '<script src="/static/analyst.js?v=6" defer></script></head><body>',
            '<header class="topbar user-topbar"><a class="brand" href="/portal">',
            '<span class="brand-mark" aria-hidden="true">L</span><span>LeakCheck Hub</span></a>',
            '<div class="user-chip"><span>',
            _h(user.email),
            "</span><small>private account</small></div></header><main>",
            content,
            "</main><footer>Your signed-in identity defines every result on this page</footer>",
            "</body></html>",
        )
    )


def _h(value: object) -> str:
    return html.escape(str(value), quote=True)
