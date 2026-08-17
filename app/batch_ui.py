"""Escaped HTML for durable scan batches."""

from __future__ import annotations

import html

from app.analyst_ui import page
from app.models import BatchStatus, ScanBatch, User


def batch_builder_page(user: User, batches: tuple[ScanBatch, ...]) -> str:
    rows = (
        "".join(
            '<tr><td><a href="/analyst/batches/'
            + str(batch.id)
            + '">'
            + _h(batch.target_type.value)
            + "</a></td><td>"
            + _h(str(batch.target))
            + "</td><td>"
            + _h(batch.status.value)
            + "</td><td>"
            + f"{batch.completed_count + batch.failed_count} / {batch.total_count}"
            + "</td></tr>"
            for batch in batches
        )
        or '<tr><td colspan="4" class="empty">No batches yet.</td></tr>'
    )
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Background operations</p>',
            "<h1>Workspace batch scans</h1><p>Targets are resolved from active synced users. ",
            "The worker processes each email under the platform rate limit.</p></section>",
            '<section class="panel"><h2>Create batch</h2>',
            '<form method="post" action="/analyst/batches">',
            '<label>Target type<select name="target_type">',
            '<option value="ou">Organizational unit</option>',
            '<option value="domain">Domain</option>',
            '<option value="selection">Selected user UUIDs</option></select></label>',
            "<label>OU path, domain, or comma-separated user UUIDs",
            '<input name="target" maxlength="8192" required></label>',
            '<button type="submit">Queue background batch</button></form></section>',
            '<section class="panel"><h2>Recent batches</h2><div class="table-wrap">',
            "<table><thead><tr><th>Type</th><th>Target</th><th>Status</th>",
            f"<th>Progress</th></tr></thead><tbody>{rows}</tbody></table></div></section>",
        )
    )
    return page("Batch scans", content, user=user)


def batch_progress_page(user: User, batch: ScanBatch) -> str:
    return page(
        "Batch progress",
        '<section class="hero compact"><p class="eyebrow">Durable background batch</p><h1>'
        + _h(batch.target_type.value)
        + ' scan</h1></section><section class="panel" aria-live="polite">'
        + batch_progress_fragment(batch)
        + "</section>",
        user=user,
    )


def batch_progress_fragment(batch: ScanBatch) -> str:
    done = batch.completed_count + batch.failed_count
    terminal = batch.status in {BatchStatus.SUCCEEDED, BatchStatus.PARTIAL, BatchStatus.FAILED}
    polling = (
        ""
        if terminal
        else (
            f' hx-get="/analyst/batches/{batch.id}/status" '
            'hx-trigger="load delay:2s" hx-swap="outerHTML"'
        )
    )
    return (
        f'<div class="scan-state"{polling}><h2>{_h(batch.status.value.title())}</h2>'
        f"<p>{done} of {batch.total_count} processed; {batch.failed_count} failed.</p>"
        f'<progress value="{done}" max="{max(batch.total_count, 1)}">{done}</progress></div>'
    )


def _h(value: str) -> str:
    return html.escape(value, quote=True)
