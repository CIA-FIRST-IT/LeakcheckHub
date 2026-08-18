"""Notification safety, deduplication, cooldown, and dry-run properties."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.models import Notification, NotificationStatus, User, UserRole, UserSource
from app.notifications import (
    MailMessage,
    deliver_next,
    enqueue_notification,
    render_portal_message,
)
from app.platform_settings import SettingKey


class _Result:
    def __init__(self, row: object = None) -> None:
        self.row = row

    def one_or_none(self) -> object:
        return self.row


class _DB:
    def __init__(self, row: object = None, *, recent: int = 0) -> None:
        self.row = row
        self.recent = recent
        self.statements: list[str] = []
        self.commits = 0

    async def execute(self, statement: object) -> _Result:
        self.statements.append(str(statement))
        return _Result(self.row)

    async def scalar(self, _: object) -> int:
        return self.recent

    async def commit(self) -> None:
        self.commits += 1


class _Store:
    def __init__(self, values: dict[SettingKey, str]) -> None:
        self.values = values

    async def read_many(self, _: object, __: object) -> dict[SettingKey, str]:
        return self.values


class _Sender:
    def __init__(self) -> None:
        self.messages: list[MailMessage] = []

    async def send(self, message: MailMessage) -> None:
        self.messages.append(message)


def _pending() -> tuple[Notification, User]:
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        email="person@example.com",
        display_name="Person",
        role=UserRole.USER,
        source=UserSource.WORKSPACE_SYNC,
    )
    notification = Notification(
        id=uuid.uuid4(),
        user_id=user_id,
        template="new_findings",
        finding_ids=[str(uuid.uuid4())],
        status=NotificationStatus.PENDING,
        dedupe_key=b"x" * 32,
        attempts=0,
        created_at=datetime(2026, 8, 17, tzinfo=UTC),
    )
    return notification, user


@pytest.mark.anyio
async def test_dry_run_defaults_on_and_never_calls_sender() -> None:
    notification, user = _pending()
    db = _DB((notification, user))
    sender = _Sender()
    assert await deliver_next(db, _Store({}), sender=sender)  # type: ignore[arg-type]
    assert notification.status is NotificationStatus.DRY_RUN
    assert sender.messages == []
    assert db.commits == 1


@pytest.mark.anyio
async def test_cooldown_suppresses_second_delivery() -> None:
    notification, user = _pending()
    db = _DB((notification, user), recent=1)
    sender = _Sender()
    values = {
        SettingKey.NOTIFY_DRY_RUN: "false",
        SettingKey.NOTIFY_COOLDOWN_SECONDS: "3600",
    }
    assert await deliver_next(db, _Store(values), sender=sender)  # type: ignore[arg-type]
    assert notification.status is NotificationStatus.SUPPRESSED
    assert sender.messages == []


@pytest.mark.anyio
async def test_enabled_delivery_sends_fixed_portal_link_message() -> None:
    notification, user = _pending()
    db = _DB((notification, user))
    sender = _Sender()
    values = {
        SettingKey.NOTIFY_DRY_RUN: "false",
        SettingKey.NOTIFY_COOLDOWN_SECONDS: "0",
        SettingKey.PUBLIC_BASE_URL: "https://leakcheck.example",
    }
    assert await deliver_next(db, _Store(values), sender=sender)  # type: ignore[arg-type]
    assert notification.status is NotificationStatus.SENT
    assert len(sender.messages) == 1
    assert sender.messages[0].recipient == "person@example.com"
    assert "https://leakcheck.example/portal" in sender.messages[0].body


@pytest.mark.anyio
async def test_double_enqueue_uses_database_unique_dedupe_key() -> None:
    db = _DB()
    user_id, finding_id = uuid.uuid4(), uuid.uuid4()
    await enqueue_notification(db, user_id=user_id, finding_ids=(finding_id,))  # type: ignore[arg-type]
    await enqueue_notification(db, user_id=user_id, finding_ids=(finding_id,))  # type: ignore[arg-type]
    assert len(db.statements) == 2
    assert all("ON CONFLICT" in statement for statement in db.statements)
    assert all("dedupe_key" in statement for statement in db.statements)


def test_rendered_body_contains_only_portal_link_and_no_password_material() -> None:
    message = render_portal_message("person@example.com", "https://leakcheck.example")
    forbidden = ("hunter2", "hu•••••", "breach source", "finding id")
    assert message.body.count("https://leakcheck.example/portal") == 1
    assert all(value not in message.body.casefold() for value in forbidden)
