"""The one HTML shell every signed-in page renders inside.

There used to be two near-identical shells, one for analysts and one for the user portal. Keeping
them in sync was manual, and it failed: the sign-out control was added to one and not the other,
and their asset versions drifted apart. Everything that differs between them follows from the
signed-in user's role, so there is one function and no options to get wrong.
"""

from __future__ import annotations

import html

from app.models import User, UserRole

_STYLESHEET = "/static/analyst.css?v=8"
_SCRIPT = "/static/analyst.js?v=7"


def esc(value: object) -> str:
    """Escape a value for HTML text or an attribute."""

    return html.escape(str(value), quote=True)


def _navigation(user: User) -> str:
    """Ordinary users have one page, so they get no navigation at all."""

    if user.role is UserRole.USER:
        return ""
    links = ['<a href="/analyst">Scan</a>']
    if user.role is UserRole.SUPER_ADMIN:
        links += [
            '<a href="/admin/settings">Settings</a>',
            '<a href="/admin/audit">Audit</a>',
            '<a href="/account/profile">Profile</a>',
        ]
    links.append('<a href="/analyst/schedules">Schedule</a>')
    return '<nav aria-label="Primary">' + "".join(links) + "</nav>"


def page(
    title: str,
    content: str,
    *,
    user: User,
    extra_styles: tuple[str, ...] = (),
    extra_scripts: tuple[str, ...] = (),
) -> str:
    """Render a complete signed-in page for any role."""

    is_user = user.role is UserRole.USER
    home = "/portal" if is_user else "/analyst"
    subtitle = "private account" if is_user else user.role.value.replace("_", " ")
    footer = (
        "Your signed-in identity defines every result on this page"
        if is_user
        else "Controlled exposure intelligence · Cleartext credentials are reveal-only"
    )
    styles = "".join(f'<link rel="stylesheet" href="{esc(path)}">' for path in extra_styles)
    scripts = "".join(f'<script src="{esc(path)}" defer></script>' for path in extra_scripts)
    return "".join(
        (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            '<meta name="htmx-config" content=\'',
            '{"includeIndicatorStyles":false,"allowEval":false,"allowScriptTags":false}',
            "'>",
            f"<title>{esc(title)} · LeakCheck Hub</title>",
            f'<link rel="stylesheet" href="{_STYLESHEET}">',
            styles,
            '<script src="/static/htmx-2.0.10.min.js" defer></script>',
            f'<script src="{_SCRIPT}" defer></script>',
            scripts,
            "</head><body>",
            f'<header class="topbar"><a class="brand" href="{home}">',
            '<span class="brand-mark" aria-hidden="true">L</span><span>LeakCheck Hub</span></a>',
            _navigation(user),
            '<div class="user-chip"><span>',
            esc(user.email),
            "</span><small>",
            esc(subtitle),
            "</small></div>",
            '<button type="button" id="sign-out" class="signout">Sign out</button>',
            "</header><main>",
            content,
            f"</main><footer>{footer}</footer>",
            "</body></html>",
        )
    )
