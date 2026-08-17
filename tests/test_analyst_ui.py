"""Analyst UI security, rendering, and reveal-action tests."""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import anyio
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.analyst_ui import (
    EventView,
    FindingView,
    _breach_date_cell,
    analyst_dashboard,
    scan_status_fragment,
    subject_history_page,
)
from app.config import Settings
from app.finding_crypto import protect_password
from app.models import (
    AuditLog,
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
    UserSource,
)
from app.platform_settings import SettingKey
from app.routers.analyst import (
    _ANALYST_GUARD,
    _csv_cell,
    _raw_breach_date,
    _raw_date,
    _raw_origin,
    _raw_value_text,
    reveal_finding_password,
)
from app.scan_runtime import configured_client

NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )


def make_user(role: UserRole = UserRole.ANALYST, *, name: str = "SOC Analyst") -> User:
    return User(
        id=uuid.uuid4(),
        email="analyst@example.test",
        display_name=name,
        role=role,
        source=UserSource.MANUAL,
    )


def make_subject() -> Subject:
    return Subject(
        id=uuid.uuid4(),
        kind=SubjectKind.EMAIL,
        value_norm="person@example.test",
        value_display="person@example.test",
    )


def test_dashboard_contains_exactly_six_supported_check_forms_and_local_htmx() -> None:
    body = analyst_dashboard(make_user(), ())

    for kind in SubjectKind:
        assert f'action="/analyst/scans/{kind.value}"' in body
    assert body.count('<article class="check-card">') == 6
    assert 'src="/static/htmx-2.0.10.min.js"' in body
    assert "cdn.jsdelivr.net" not in body
    assert '"allowEval":false' in body
    assert '"allowScriptTags":false' in body
    assert 'type="password"' in body
    assert "cleartext is sent to LeakCheck" in body
    assert ">Scan</a>" in body
    assert '<a href="/analyst/schedules">Schedule</a>' in body
    assert "Settings" not in body
    assert "Profile" not in body
    assert "Notifications" not in body
    assert "Watchlist" not in body

    admin_body = analyst_dashboard(make_user(UserRole.SUPER_ADMIN), ())
    assert '<a href="/admin/settings">Settings</a>' in admin_body
    assert '<a href="/account/profile">Profile</a>' in admin_body


def test_pending_scan_uses_polling_and_failure_never_displays_error_detail() -> None:
    scan = Scan(
        id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        trigger=ScanTrigger.MANUAL,
        status=ScanStatus.PENDING,
        result_count=0,
        new_count=0,
        truncated=False,
    )

    pending = scan_status_fragment(scan)
    assert f'hx-get="/analyst/scans/{scan.id}/status"' in pending
    assert 'hx-trigger="load delay:1s"' in pending

    scan.status = ScanStatus.FAILED
    scan.error = "LeakCheckUnavailable: secret vendor response"
    failed = scan_status_fragment(scan)
    assert "The check could not be completed" in failed
    assert scan.error not in failed


def test_vendor_and_identity_xss_payloads_are_rendered_inert() -> None:
    subject = make_subject()
    payload = '<img src=x onerror="alert(1)">'
    finding = FindingView(
        id=uuid.uuid4(),
        source=f"Breach {payload}",
        breach_date=date(2026, 1, 2),
        breach_date_text="2026-01-02",
        collected_date=date(2025, 3, 19),
        fields=(payload, "email"),
        email=f"victim+{payload}@example.test",
        username=payload,
        phone=payload,
        origin=f"https://example.test/{payload}",
        password_mask=payload,  # noqa: S106 - hostile synthetic vendor-derived display value
        has_password=True,
        remediated_at=None,
        re_leaked=True,
        first_seen_at=NOW,
        last_seen_at=NOW,
        raw={"vendor": payload, "nested": {"html": "<script>alert(1)</script>"}},
    )
    event = EventView(
        event=FindingEventType.DISCOVERED,
        at=NOW,
        actor=payload,
        meta={"payload": payload},
    )

    body = subject_history_page(make_user(name=payload), subject, (finding,), (event,))

    assert payload not in body
    assert "<script>alert(1)</script>" not in body
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert 'class="releaked"' in body
    assert "02-01-2026" in body
    assert "19-03-2025" in body
    assert "17-08-2026 12:00" in body
    assert 'id="result-search"' in body
    assert 'class="sort-button"' in body
    assert 'data-copy-value="victim+' in body
    assert 'id="findings-page-size"' in body
    assert 'value="100"' in body
    assert 'value="all"' in body
    assert "data-resize-handle" in body
    partial = replace(finding, breach_date=None, breach_date_text="2019-04")
    assert ">04-2019</td>" in _breach_date_cell(partial)


def test_list_origin_collected_date_and_raw_search_use_values_only() -> None:
    raw = {
        "origin": ["bill24.net"],
        "collected": "2025-03-19",
        "nested_key_that_must_not_match": {"email": "person@example.test"},
    }

    assert _raw_origin(raw["origin"]) == "bill24.net"
    assert _raw_date(raw["collected"]) == date(2025, 3, 19)
    flattened = _raw_value_text(raw)
    assert "bill24.net" in flattened
    assert "person@example.test" in flattened
    assert "nested_key_that_must_not_match" not in flattened
    assert _raw_breach_date({"source": {"breach_date": "2019-04"}}, {}) == "2019-04"


@pytest.mark.anyio
async def test_analyst_guard_rejects_user_but_accepts_analyst_and_superadmin() -> None:
    with pytest.raises(HTTPException) as rejected:
        await _ANALYST_GUARD(current_user=make_user(UserRole.USER))
    assert rejected.value.status_code == 403

    assert await _ANALYST_GUARD(current_user=make_user(UserRole.ANALYST))
    assert await _ANALYST_GUARD(current_user=make_user(UserRole.SUPER_ADMIN))


@dataclass
class FakeResult:
    finding: Finding | None

    def scalar_one_or_none(self) -> Finding | None:
        return self.finding


@dataclass
class FakeDB:
    finding: Finding | None
    added: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    async def execute(self, statement: object) -> FakeResult:
        sql = str(statement)
        assert "password_ciphertext" in sql
        assert "password_nonce" in sql
        return FakeResult(self.finding)

    def add(self, value: object) -> None:
        self.added.append(value)


def make_request(settings: Settings) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(settings=settings))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/analyst/findings/reveal",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 443),
            "scheme": "https",
            "app": app,
        }
    )


@dataclass
class FakePlatformStore:
    values: dict[SettingKey, str]

    async def read_many(self, db: object, keys: object) -> dict[SettingKey, str]:
        del db, keys
        return self.values


@pytest.mark.anyio
async def test_configured_client_is_shared_until_platform_settings_change() -> None:
    store = FakePlatformStore({SettingKey.LEAKCHECK_API_KEY: "configured-fixture-key"})
    app = SimpleNamespace(
        state=SimpleNamespace(
            platform_settings=store,
            leakcheck_client=None,
            leakcheck_client_config_digest=None,
            leakcheck_client_lock=anyio.Lock(),
        )
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/analyst/scans/email",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 443),
            "scheme": "https",
            "app": app,
        }
    )

    first = await configured_client(request, object())  # type: ignore[arg-type]
    second = await configured_client(request, object())  # type: ignore[arg-type]
    assert first is second

    store.values = {SettingKey.LEAKCHECK_API_KEY: "rotated-fixture-key"}
    rotated = await configured_client(request, object())  # type: ignore[arg-type]
    assert rotated is not first


@pytest.mark.anyio
async def test_reveal_decrypts_once_and_appends_event_and_audit_without_unescaped_html() -> None:
    settings = make_settings()
    finding_id = uuid.uuid4()
    cleartext = '<script>alert("credential")</script>'
    protected = protect_password(settings, finding_id=finding_id, password=cleartext)
    finding = Finding(
        id=finding_id,
        subject_id=uuid.uuid4(),
        source_id=uuid.uuid4(),
        password_ciphertext=protected.ciphertext,
        password_nonce=protected.nonce,
        password_sha256=protected.sha256,
        password_mask=protected.mask,
        password_len=protected.length,
        password_charset=protected.charset,
        fingerprint=b"f" * 32,
        severity=FindingSeverity.MEDIUM,
        fields=[],
        raw={},
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    db = FakeDB(finding)
    actor = make_user()

    response = await reveal_finding_password(
        finding_id,
        make_request(settings),
        current_user=actor,
        db=db,  # type: ignore[arg-type]
    )

    body = response.body.decode()
    assert cleartext not in body
    assert "&lt;script&gt;" in body
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert len(db.added) == 2
    assert isinstance(db.added[0], FindingEvent)
    assert db.added[0].event is FindingEventType.PASSWORD_VIEWED
    assert db.added[0].actor_id == actor.id
    assert isinstance(db.added[1], AuditLog)
    assert db.added[1].action == "finding.password_viewed"
    assert db.added[1].target_id == str(finding_id)


@pytest.mark.parametrize("dangerous", ["=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "\tformula"])
def test_csv_export_neutralizes_spreadsheet_formulas(dangerous: str) -> None:
    assert _csv_cell(dangerous) == "'" + dangerous


def test_csv_export_leaves_ordinary_vendor_values_unchanged() -> None:
    assert _csv_cell("Canva") == "Canva"
