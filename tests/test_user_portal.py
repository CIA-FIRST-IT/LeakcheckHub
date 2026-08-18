"""Self-service anti-IDOR, masking, cooldown, and rendering tests."""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

import app.user_views as user_views_module
from app.models import Scan, ScanStatus, ScanTrigger, SubjectKind, User, UserRole, UserSource
from app.normalization import normalize_subject
from app.routers.analyst import _ANALYST_GUARD
from app.routers.user import (
    _PORTAL_GUARD,
    _owned_finding_statement,
    _user_findings_statement,
    cooldown_remaining,
    self_check,
)
from app.user_ui import dashboard_page, progress_fragment
from app.user_views import UserFindingProjection, serialize_user_finding

NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)
CLEARTEXT_SENTINEL = "NeverReturnThis-Credential-42!"


def make_user(role: UserRole = UserRole.USER, *, name: str = "Portal User") -> User:
    return User(
        id=uuid.uuid4(),
        email="person@example.test",
        display_name=name,
        role=role,
        source=UserSource.MANUAL,
    )


def make_projection(**overrides: object) -> UserFindingProjection:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "source": "Canva",
        "breach_date": date(2026, 1, 2),
        "fields": ("email", "password"),
        "origin": "https://canva.example.test",
        "password_mask": "Ne••••!",  # noqa: S106 - deliberately masked fixture
        "remediated_at": None,
        "re_leaked": True,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
    }
    values.update(overrides)
    return UserFindingProjection(**values)  # type: ignore[arg-type]


def test_masked_serializer_has_a_fixed_allow_list_and_no_credential_storage_path() -> None:
    source = inspect.getsource(user_views_module)
    forbidden_column = "password_" + "ciphertext"
    assert forbidden_column not in source
    assert "from app.models import Finding" not in source

    serialized = serialize_user_finding(make_projection())
    assert set(serialized) == {
        "id",
        "source",
        "breach_date",
        "fields",
        "origin",
        "password_mask",
        "remediated",
        "re_leaked",
        "first_seen_at",
        "last_seen_at",
        "guidance",
    }
    assert CLEARTEXT_SENTINEL not in repr(serialized)


def test_user_query_selects_only_safe_columns_and_is_bound_to_session_email() -> None:
    normalized = normalize_subject(SubjectKind.EMAIL, "PERSON@EXAMPLE.TEST")
    sql = str(
        _user_findings_statement(normalized).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )

    assert "subjects.value_norm = 'person@example.test'" in sql
    assert "findings.password_mask" in sql
    assert "findings.password_ciphertext" not in sql
    assert "findings.password_nonce" not in sql
    assert "findings.password_sha256" not in sql


def test_self_remediation_ownership_statement_combines_finding_and_session_email() -> None:
    finding_id = uuid.uuid4()
    normalized = normalize_subject(SubjectKind.EMAIL, "person@example.test")
    sql = str(
        _owned_finding_statement(finding_id, normalized).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )

    assert str(finding_id) in sql
    assert "subjects.value_norm = 'person@example.test'" in sql
    assert "subjects.kind = 'email'" in sql
    assert "FOR UPDATE" in sql


def test_self_check_route_exposes_no_identifier_or_payload_parameter() -> None:
    parameters = inspect.signature(self_check).parameters
    assert set(parameters) == {"request", "background_tasks", "current_user", "db"}
    assert not {"email", "query", "subject", "identifier", "payload"}.intersection(parameters)


def test_user_dashboard_escapes_breach_data_and_never_contains_known_cleartext() -> None:
    xss = '<img src=x onerror="alert(1)">'
    projection = make_projection(
        source=xss,
        fields=(xss, "email"),
        origin=xss,
        password_mask=xss,
    )
    body = dashboard_page(
        make_user(name=xss),
        (serialize_user_finding(projection),),
        can_check=True,
    )

    assert xss not in body
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in body
    assert CLEARTEXT_SENTINEL not in body
    assert 'href="/analyst"' not in body
    assert 'action="/portal/check"' in body
    assert 'name="email"' not in body
    assert "person@example.test" in body
    assert ">Scan now</button>" in body
    assert '<nav aria-label="Primary">' not in body


@pytest.mark.anyio
async def test_portal_guard_accepts_every_authenticated_role() -> None:
    for role in UserRole:
        user = make_user(role)
        assert await _PORTAL_GUARD(current_user=user) is user


@pytest.mark.anyio
async def test_ordinary_user_cannot_enter_any_analyst_route_guard() -> None:
    with pytest.raises(HTTPException) as rejected:
        await _ANALYST_GUARD(current_user=make_user(UserRole.USER))
    assert rejected.value.status_code == 403


def test_self_check_cooldown_counts_from_scan_start_and_never_goes_negative() -> None:
    scan = Scan(
        id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        requested_by=uuid.uuid4(),
        trigger=ScanTrigger.SELF,
        status=ScanStatus.SUCCEEDED,
        started_at=NOW - timedelta(minutes=10),
        result_count=0,
        new_count=0,
        truncated=False,
    )

    assert cooldown_remaining(scan, cooldown_seconds=3600, now=NOW) == 3000
    assert cooldown_remaining(scan, cooldown_seconds=60, now=NOW) == 0
    assert cooldown_remaining(None, cooldown_seconds=3600, now=NOW) == 0


def test_failed_progress_never_reflects_persisted_error_detail() -> None:
    scan = Scan(
        id=uuid.uuid4(),
        subject_id=uuid.uuid4(),
        requested_by=uuid.uuid4(),
        trigger=ScanTrigger.SELF,
        status=ScanStatus.FAILED,
        error=f"VendorFailure: {CLEARTEXT_SENTINEL}",
        result_count=0,
        new_count=0,
        truncated=False,
    )

    body = progress_fragment(scan)
    assert CLEARTEXT_SENTINEL not in body
    assert scan.error not in body
