"""Deduplicated, cooldown-aware email notifications with dry-run defaulting on."""

from __future__ import annotations

import asyncio
import hashlib
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Protocol, cast

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, Notification, NotificationStatus, Subject, User
from app.platform_settings import PlatformSettingError, PlatformSettingsStore, SettingKey

_TEMPLATE = "new_findings"
_DIGEST_TEMPLATE = "findings_digest"


class NotificationConfigurationError(Exception):
    """Mail delivery was enabled without complete secure SMTP settings."""


@dataclass(frozen=True, slots=True)
class MailMessage:
    recipient: str
    subject: str
    body: str


@dataclass(frozen=True, slots=True)
class SMTPConfig:
    host: str
    port: int
    username: str | None
    password: str | None
    sender: str
    security: str


class MailSender(Protocol):
    async def send(self, message: MailMessage) -> None: ...


class SMTPMailSender:
    """TLS-only stdlib SMTP transport executed outside the async event loop."""

    def __init__(self, config: SMTPConfig) -> None:
        self._config = config

    async def send(self, message: MailMessage) -> None:
        await asyncio.to_thread(self._send_sync, message)

    def _send_sync(self, message: MailMessage) -> None:
        email = EmailMessage()
        email["From"] = self._config.sender
        email["To"] = message.recipient
        email["Subject"] = message.subject
        email.set_content(message.body)
        context = ssl.create_default_context()
        if self._config.security == "tls":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                self._config.host, self._config.port, timeout=30, context=context
            )
        else:
            smtp = smtplib.SMTP(self._config.host, self._config.port, timeout=30)
        with smtp:
            if self._config.security == "starttls":
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
            if self._config.username:
                smtp.login(self._config.username, self._config.password or "")
            smtp.send_message(email)


async def enqueue_notification(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    finding_ids: tuple[uuid.UUID, ...],
    template: str = _TEMPLATE,
) -> None:
    """Insert once even when multiple scans or double-submits request the same message."""

    ids = tuple(sorted({str(item) for item in finding_ids}))
    if not ids:
        return
    await db.execute(
        postgresql_insert(Notification)
        .values(
            id=uuid.uuid4(),
            user_id=user_id,
            template=template,
            finding_ids=list(ids),
            dedupe_key=_dedupe_key(user_id, template, ids),
        )
        .on_conflict_do_nothing(constraint="uq_notifications_dedupe_key")
    )


async def enqueue_new_findings(
    db: AsyncSession, *, subject: Subject, finding_ids: tuple[uuid.UUID, ...]
) -> None:
    if subject.linked_user_id is not None and finding_ids:
        await enqueue_notification(
            db, user_id=subject.linked_user_id, finding_ids=finding_ids, template=_TEMPLATE
        )


async def enqueue_digest_notifications(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Queue one deduplicated digest per user for current unremediated findings."""

    digest_template = f"{_DIGEST_TEMPLATE}:{(now or datetime.now(UTC)).date().isoformat()}"
    result = await db.execute(
        select(User.id, Finding.id)
        .join(Subject, Subject.linked_user_id == User.id)
        .join(Finding, Finding.subject_id == Subject.id)
        .where(User.is_active.is_(True), Finding.remediated_at.is_(None))
        .order_by(User.id, Finding.id)
    )
    grouped: dict[uuid.UUID, list[uuid.UUID]] = {}
    for user_id, finding_id in result.all():
        grouped.setdefault(cast(uuid.UUID, user_id), []).append(cast(uuid.UUID, finding_id))
    for user_id, finding_ids in grouped.items():
        await enqueue_notification(
            db,
            user_id=user_id,
            finding_ids=tuple(finding_ids),
            template=digest_template,
        )
    return len(grouped)


async def deliver_next(
    db: AsyncSession,
    store: PlatformSettingsStore,
    *,
    sender: MailSender | None = None,
    now: datetime | None = None,
) -> bool:
    """Lock and finish one outbox item; dry-run never constructs an SMTP sender."""

    current = now or datetime.now(UTC)
    result = await db.execute(
        select(Notification, User)
        .join(User, User.id == Notification.user_id)
        .where(Notification.status == NotificationStatus.PENDING)
        .order_by(Notification.created_at, Notification.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    row = result.one_or_none()
    if row is None:
        return False
    notification, user = cast(tuple[Notification, User], row)
    notification.attempts += 1
    values = await store.read_many(db, frozenset(SettingKey))
    if _bool_setting(values.get(SettingKey.NOTIFY_DRY_RUN), default=True):
        notification.status = NotificationStatus.DRY_RUN
        await db.commit()
        return True
    cooldown = _int_setting(values.get(SettingKey.NOTIFY_COOLDOWN_SECONDS), 86_400)
    recent = await db.scalar(
        select(func.count(Notification.id)).where(
            Notification.user_id == user.id,
            Notification.status == NotificationStatus.SENT,
            Notification.sent_at > current - timedelta(seconds=cooldown),
        )
    )
    if cooldown and int(recent or 0) > 0:
        notification.status = NotificationStatus.SUPPRESSED
        notification.error = "notification cooldown active"
        await db.commit()
        return True
    try:
        base_url = _base_url(values)
        resolved_sender = sender or SMTPMailSender(_smtp_config(values))
        await resolved_sender.send(render_portal_message(str(user.email), base_url))
    except Exception as exc:
        notification.status = NotificationStatus.FAILED
        notification.error = type(exc).__name__
    else:
        notification.status = NotificationStatus.SENT
        notification.sent_at = current
        notification.error = None
    await db.commit()
    return True


def render_portal_message(recipient: str, base_url: str) -> MailMessage:
    """Render no finding fields, credentials, password masks, or breach data—only a portal link."""

    return MailMessage(
        recipient=recipient,
        subject="LeakCheck Hub: security action available",
        body=(
            "LeakCheck Hub has security information requiring your review.\n\n"
            f"Sign in to review and remediate it: {base_url}/portal\n\n"
            "For your protection, exposure details are available only after sign-in."
        ),
    )


def _smtp_config(values: dict[SettingKey, str]) -> SMTPConfig:
    try:
        host = values[SettingKey.SMTP_HOST]
        port = int(values[SettingKey.SMTP_PORT])
        sender = values[SettingKey.SMTP_FROM]
        security = values.get(SettingKey.SMTP_SECURITY, "starttls")
    except (KeyError, ValueError) as exc:
        raise NotificationConfigurationError("SMTP is not configured") from exc
    if not host or not sender or security not in {"starttls", "tls"} or not 1 <= port <= 65535:
        raise NotificationConfigurationError("SMTP is not configured")
    return SMTPConfig(
        host,
        port,
        values.get(SettingKey.SMTP_USERNAME),
        values.get(SettingKey.SMTP_PASSWORD),
        sender,
        security,
    )


def _base_url(values: dict[SettingKey, str]) -> str:
    value = values.get(SettingKey.PUBLIC_BASE_URL, "").rstrip("/")
    if not value.startswith("https://"):
        raise NotificationConfigurationError("public base URL is not configured")
    return value


def _dedupe_key(user_id: uuid.UUID, template: str, ids: tuple[str, ...]) -> bytes:
    digest = hashlib.sha256(b"leakcheck/notification/v1\x00" + user_id.bytes)
    digest.update(template.encode("ascii"))
    for finding_id in ids:
        digest.update(finding_id.encode("ascii"))
    return digest.digest()


def _bool_setting(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    if value.casefold() in {"true", "1", "yes", "on"}:
        return True
    if value.casefold() in {"false", "0", "no", "off"}:
        return False
    raise PlatformSettingError("invalid stored boolean setting")


def _int_setting(value: str | None, default: int) -> int:
    parsed = default if value is None else int(value)
    if not 0 <= parsed <= 30 * 24 * 60 * 60:
        raise PlatformSettingError("invalid notification cooldown")
    return parsed
