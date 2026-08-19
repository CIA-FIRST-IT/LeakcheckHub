"""Escaped analyst watchlist management UI."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.layout import esc as _h
from app.layout import page
from app.models import User, WatchlistEntry


@dataclass(frozen=True, slots=True)
class WatchlistView:
    entry: WatchlistEntry
    target_label: str


def watchlist_page(user: User, entries: tuple[WatchlistView, ...]) -> str:
    rows = "".join(_row(view) for view in entries) or (
        '<tr><td colspan="7" class="empty">No watchlist entries.</td></tr>'
    )
    content = "".join(
        (
            '<section class="hero compact"><p class="eyebrow">High-value identities</p>',
            "<h1>Watchlist</h1><p>New and re-leaked findings are copied to the durable ",
            "alert outbox. SIEM adapters remain inactive until their live contracts are ",
            "verified.</p>",
            '</section><section class="panel"><h2>Add entry</h2>',
            '<form method="post" action="/analyst/watchlist">',
            '<label>Target type<select name="target_type"><option value="user">User email</option>',
            '<option value="subject">Subject UUID</option></select></label>',
            '<label>Target<input name="target" maxlength="320" required></label>',
            _checkbox("alert_soc", "SOC email", True),
            _checkbox("alert_user", "User email", True),
            _checkbox("alert_wazuh", "Wazuh", True),
            _checkbox("alert_iris", "DFIR-IRIS", True),
            '<button type="submit">Add to watchlist</button></form></section>',
            '<section class="panel"><h2>Entries</h2><div class="table-wrap"><table>',
            "<thead><tr><th>Target</th><th>SOC</th><th>User</th><th>Wazuh</th>",
            f"<th>IRIS</th><th>Enabled</th><th>Action</th></tr></thead><tbody>{rows}</tbody>",
            "</table></div></section>",
        )
    )
    return page("Watchlist", content, user=user)


def _row(view: WatchlistView) -> str:
    entry = view.entry
    cells = "".join(
        _toggle_cell(entry.id, channel, value)
        for channel, value in (
            ("alert_soc", entry.alert_soc),
            ("alert_user", entry.alert_user),
            ("alert_wazuh", entry.alert_wazuh),
            ("alert_iris", entry.alert_iris),
            ("enabled", entry.enabled),
        )
    )
    return (
        f"<tr><td>{_h(view.target_label)}</td>{cells}<td>"
        f'<form method="post" action="/analyst/watchlist/{entry.id}/delete">'
        '<button type="submit" class="secondary">Remove</button></form></td></tr>'
    )


def _toggle_cell(entry_id: uuid.UUID, channel: str, value: bool) -> str:
    return (
        '<td><form method="post" action="/analyst/watchlist/'
        + str(entry_id)
        + "/toggle/"
        + channel
        + '"><button type="submit" class="link-button">'
        + ("yes" if value else "no")
        + "</button></form></td>"
    )


def _checkbox(name: str, label: str, checked: bool) -> str:
    marker = " checked" if checked else ""
    return f'<label><input type="checkbox" name="{name}" value="true"{marker}> {_h(label)}</label>'
