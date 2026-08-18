"""Escaped two-step notification campaign UI."""

from __future__ import annotations

import html

from app.analyst_ui import page
from app.models import Notification, User


def notifications_page(user: User, notifications: tuple[Notification, ...]) -> str:
    rows = (
        "".join(
            f"<tr><td>{item.created_at.isoformat()}</td><td>{_h(item.template)}</td>"
            f"<td>{_h(item.status.value)}</td><td>{len(item.finding_ids)}</td></tr>"
            for item in notifications
        )
        or '<tr><td colspan="4" class="empty">No notification attempts.</td></tr>'
    )
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Safe outreach</p>',
            "<h1>User notifications</h1><p>Messages contain only a portal link. ",
            "Dry-run is enabled unless a super-admin explicitly disables it.</p></section>",
            '<section class="panel"><h2>Prepare campaign</h2>',
            '<form method="post" action="/analyst/notifications/preview">',
            '<label>Target type<select name="target_type"><option value="user">User email</option>',
            '<option value="ou">Organizational unit</option>',
            '<option value="domain">Domain</option>',
            '<option value="selection">Selected user UUIDs</option></select></label>',
            "<label>Email, OU path, domain, or comma-separated UUIDs",
            '<input name="target" maxlength="8192" required></label>',
            '<button type="submit">Preview recipients</button></form></section>',
            '<section class="panel"><h2>Recent attempts</h2><div class="table-wrap">',
            "<table><thead><tr><th>Created</th><th>Template</th><th>Status</th>",
            f"<th>Findings</th></tr></thead><tbody>{rows}</tbody></table></div></section>",
        )
    )
    return page("Notifications", content, user=user)


def confirmation_page(user: User, target_type: str, target: str, recipient_count: int) -> str:
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">Explicit confirmation</p>',
            '<h1>Confirm notification campaign</h1></section><section class="panel">',
            f"<p><strong>{recipient_count}</strong> active users with open findings ",
            "match this target.</p>",
            "<p>Email bodies will contain only a link to the authenticated portal.</p>",
            '<form method="post" action="/analyst/notifications/confirm">',
            f'<input type="hidden" name="target_type" value="{_h(target_type)}">',
            f'<input type="hidden" name="target" value="{_h(target)}">',
            '<button type="submit">Confirm and queue</button>',
            '<a class="button secondary" href="/analyst/notifications">Cancel</a></form></section>',
        )
    )
    return page("Confirm notifications", content, user=user)


def _h(value: str) -> str:
    return html.escape(value, quote=True)
