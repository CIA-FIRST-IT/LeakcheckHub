"""Rotate the root data key across every ciphertext the portal stores.

Three stores are encrypted under ``LC_DATA_KEY``: finding passwords, platform settings, and
super-admin TOTP seeds. All three must be rewritten together, inside one transaction, or the
deployment is left partly unreadable. Run this with the application stopped.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import secrets
import sys
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.auth.local import _totp_aad
from app.config import get_settings
from app.finding_crypto import _aad as _finding_aad
from app.models import AdminCredential, Finding, PlatformSetting
from app.platform_settings import PlatformSettingsStore, SettingKey

# Imported rather than restated: an associated-data string that drifts from the writer silently
# turns every rotation into unrecoverable data loss.
_TOTP_NONCE_BYTES = 12


def decode_key(value: str) -> bytes:
    """Decode a base64url data key and reject anything that is not a 256-bit key."""

    raw = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    if len(raw) != 32:
        raise ValueError("a data key must decode to exactly 32 bytes")
    return raw


@dataclass
class RotationReport:
    findings: int = 0
    settings: int = 0
    totp_secrets: int = 0
    failures: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"findings={self.findings} settings={self.settings} "
            f"totp_secrets={self.totp_secrets} failures={len(self.failures)}"
        )


def _recrypt(old: AESGCM, new: AESGCM, *, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return new.encrypt(nonce, old.decrypt(nonce, ciphertext, aad), aad)


async def rotate(db: AsyncSession, *, old_key: bytes, new_key: bytes) -> RotationReport:
    """Re-encrypt every stored ciphertext, preserving each nonce and its bound associated data."""

    old, new = AESGCM(old_key), AESGCM(new_key)
    report = RotationReport()

    findings = await db.execute(
        select(Finding).where(Finding.password_ciphertext.is_not(None)).with_for_update()
    )
    for finding in findings.scalars():
        if finding.password_ciphertext is None or finding.password_nonce is None:
            continue
        try:
            finding.password_ciphertext = _recrypt(
                old,
                new,
                nonce=finding.password_nonce,
                ciphertext=finding.password_ciphertext,
                aad=_finding_aad(finding.id),
            )
            report.findings += 1
        except InvalidTag:
            report.failures.append(f"finding:{finding.id}")

    rows = await db.execute(select(PlatformSetting).with_for_update())
    for row in rows.scalars():
        aad = PlatformSettingsStore._aad(SettingKey(row.key), row.schema_version)
        try:
            row.ciphertext = _recrypt(old, new, nonce=row.nonce, ciphertext=row.ciphertext, aad=aad)
            report.settings += 1
        except InvalidTag:
            report.failures.append(f"platform_setting:{row.key}")

    credentials = await db.execute(
        select(AdminCredential)
        .where(AdminCredential.totp_secret_enc.is_not(None))
        .with_for_update()
    )
    for credential in credentials.scalars():
        blob = credential.totp_secret_enc
        if blob is None or len(blob) <= _TOTP_NONCE_BYTES:
            continue
        nonce, ciphertext = blob[:_TOTP_NONCE_BYTES], blob[_TOTP_NONCE_BYTES:]
        try:
            credential.totp_secret_enc = nonce + _recrypt(
                old,
                new,
                nonce=nonce,
                ciphertext=ciphertext,
                aad=_totp_aad(credential.user_id),
            )
            report.totp_secrets += 1
        except InvalidTag:
            report.failures.append(f"admin_credential:{credential.user_id}")

    return report


async def _run(new_key_value: str, *, dry_run: bool) -> RotationReport:
    settings = get_settings()
    old_key = decode_key(settings.data_key.get_secret_value())
    new_key = decode_key(new_key_value)
    if old_key == new_key:
        raise SystemExit("the new data key is identical to the current one")

    engine = create_async_engine(settings.database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as db:
            report = await rotate(db, old_key=old_key, new_key=new_key)
            if report.failures:
                await db.rollback()
            elif dry_run:
                await db.rollback()
            else:
                await db.commit()
            return report
    finally:
        await engine.dispose()


def generate_key() -> str:
    """Produce a base64url 32-byte key in the form the application expects."""

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m app.reencrypt",
        description="Rotate LC_DATA_KEY across findings, platform settings, and TOTP seeds.",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="print a new base64url 32-byte key and exit without touching the database",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="decrypt and re-encrypt everything, then roll back without writing",
    )
    arguments = parser.parse_args()

    if arguments.generate:
        print(generate_key())
        return

    # Deliberately has no --new-key option, matching create_superadmin: a root data key passed as
    # an argument is visible in shell history and in the process list to every user on the host.
    new_key_value = getpass.getpass("New data key (base64url, 32 bytes): ").strip()
    if not new_key_value:
        raise SystemExit("no key supplied")
    if getpass.getpass("Confirm new data key: ").strip() != new_key_value:
        raise SystemExit("the two keys did not match")

    report = asyncio.run(_run(new_key_value, dry_run=arguments.dry_run))
    if report.failures:
        print("rotation aborted; nothing was written", file=sys.stderr)
        for failure in report.failures[:20]:
            print(f"  could not decrypt {failure}", file=sys.stderr)
        raise SystemExit(1)
    verb = "would rotate" if arguments.dry_run else "rotated"
    print(f"{verb}: {report.summary()}")
    if not arguments.dry_run:
        print("Update LC_DATA_KEY (or the data-key bootstrap secret) before restarting the app.")


if __name__ == "__main__":
    main()
