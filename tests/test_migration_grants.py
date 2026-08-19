"""Every table the runtime role touches must be granted to it explicitly.

The database uses least-privilege roles: migrations run as leakcheck_migrator and create tables,
while the application connects as leakcheck_runtime. A new table therefore has no runtime access
until a migration grants it, and the failure appears only at request time as a 500. This check
runs statically so the omission is caught before deployment.
"""

from __future__ import annotations

import re
from pathlib import Path

_MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations" / "versions"
_CREATE = re.compile(r'op\.create_table\(\s*["\']([a-z_]+)["\']')
_GRANT = re.compile(
    r"GRANT\s+([A-Z, ]+?)\s+ON\s+(?:TABLE\s+)?([a-z_, ]+?)\s+TO\s+leakcheck_runtime"
)

# Tables the application never reads through the runtime role.
_NO_RUNTIME_ACCESS = {
    "apscheduler_jobs",  # owned and used by the scheduler's own connection
}


def _sources() -> str:
    return "\n".join(p.read_text() for p in sorted(_MIGRATIONS.glob("*.py")))


# 0005 grants in a loop: `for table in (...): op.execute(f"GRANT ... {table} ...")`.
_LOOP = re.compile(r"for\s+(\w+)\s+in\s+\(([^)]*)\):", re.S)


def _granted_tables(text: str) -> set[str]:
    granted: set[str] = set()
    for _, tables in _GRANT.findall(text):
        granted.update(name.strip() for name in tables.split(",") if name.strip())
    for variable, members in _LOOP.findall(text):
        if f"{{{variable}}}" not in text or "leakcheck_runtime" not in text:
            continue
        granted.update(re.findall(r'["\']([a-z_]+)["\']', members))
    return granted


def test_every_created_table_grants_access_to_the_runtime_role() -> None:
    text = _sources()
    created = set(_CREATE.findall(text)) - _NO_RUNTIME_ACCESS

    missing = sorted(created - _granted_tables(text))

    assert not missing, (
        f"tables created without granting leakcheck_runtime: {missing}. "
        "The application connects as that role and will fail with a 500 at request time."
    )


def test_retention_can_actually_delete_what_it_is_asked_to_delete() -> None:
    """Configurable retention removes findings and their events; both need DELETE."""

    text = _sources()

    for table in ("findings", "finding_events"):
        assert re.search(rf"GRANT\s+DELETE\s+ON\s+{table}\s+TO\s+leakcheck_runtime", text), (
            f"retention deletes from {table} but the runtime role was never granted DELETE"
        )
