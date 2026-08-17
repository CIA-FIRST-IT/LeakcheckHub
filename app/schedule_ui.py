"""Escaped schedule management pages."""

from __future__ import annotations

import html
from datetime import datetime

from app.analyst_ui import page
from app.models import Schedule, User


def schedules_page(user: User, schedules: tuple[Schedule, ...]) -> str:
    rows = "".join(_row(schedule) for schedule in schedules) or (
        '<tr><td colspan="7" class="empty">No schedules configured.</td></tr>'
    )
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Recurring operations</p>',
            "<h1>Schedules</h1><p>Cron times use the selected IANA timezone. ",
            "Runs are persisted and dispatched by one advisory-lock leader.</p></section>",
            '<section class="panel"><h2>Create schedule</h2>',
            '<form method="post" action="/analyst/schedules">',
            '<label>Kind<select name="kind"><option value="scan_ou">OU scan</option>',
            '<option value="scan_domain">Domain scan</option>',
            '<option value="digest">Unremediated findings digest</option></select></label>',
            '<label>OU path or domain<input name="target" maxlength="1024" required></label>',
            '<label>Cron<input name="cron" value="0 2 * * *" maxlength="255" required></label>',
            '<label>Timezone<input name="timezone" value="UTC" maxlength="255" required ',
            'hx-get="/analyst/schedules/preview" hx-trigger="change delay:300ms" ',
            'hx-include="closest form" hx-target="#next-preview"></label>',
            '<label>Misfire grace (seconds)<input type="number" name="misfire_grace_seconds" ',
            'value="300" min="0" max="86400"></label>',
            '<p id="next-preview">Enter a valid cron and timezone to preview the next run.</p>',
            '<button type="submit">Create schedule</button></form></section>',
            '<section class="panel"><h2>Configured schedules</h2><div class="table-wrap">',
            "<table><thead><tr><th>Kind</th><th>Target</th><th>Cron</th><th>Timezone</th>",
            "<th>Next run</th><th>Status</th><th>Actions</th></tr></thead>",
            f"<tbody>{rows}</tbody></table></div></section>",
        )
    )
    return page("Schedules", content, user=user)


def preview_fragment(next_run: datetime) -> str:
    return "Next run: <strong>" + _h(next_run.isoformat()) + "</strong>"


def _row(schedule: Schedule) -> str:
    action = "Disable" if schedule.enabled else "Enable"
    error = f"<br><small>{_h(schedule.last_error)}</small>" if schedule.last_error else ""
    return "".join(
        (
            f"<tr><td>{_h(schedule.kind.value)}</td><td>{_h(schedule.target)}</td>",
            f"<td><code>{_h(schedule.cron)}</code></td><td>{_h(schedule.timezone)}</td>",
            f"<td>{_h(schedule.next_run_at.isoformat())}{error}</td>",
            f"<td>{'enabled' if schedule.enabled else 'disabled'}</td><td>",
            f'<form method="post" action="/analyst/schedules/{schedule.id}/toggle">',
            f'<button type="submit">{action}</button></form>',
            f'<form method="post" action="/analyst/schedules/{schedule.id}/delete">',
            '<button type="submit" class="secondary">Delete</button></form></td></tr>',
        )
    )


def _h(value: str) -> str:
    return html.escape(value, quote=True)
