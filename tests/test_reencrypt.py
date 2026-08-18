"""Root data-key rotation tests.

A rotation that silently corrupts a store is unrecoverable, so these tests assert the real
associated data is reproduced for all three encrypted stores, not merely that bytes changed.
"""

from __future__ import annotations

import base64
import secrets
import uuid

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.auth.local import _totp_aad
from app.finding_crypto import _aad as _finding_aad
from app.models import AdminCredential, Finding, PlatformSetting
from app.platform_settings import PlatformSettingsStore, SettingKey
from app.reencrypt import decode_key, rotate

_OLD = secrets.token_bytes(32)
_NEW = secrets.token_bytes(32)


class _Result:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> list[object]:
        return self._rows


class _RotationSession:
    def __init__(self, findings: list[object], settings: list[object], creds: list[object]) -> None:
        self._batches = [_Result(findings), _Result(settings), _Result(creds)]

    async def execute(self, *_: object, **__: object) -> _Result:
        return self._batches.pop(0)


def _finding(password: bytes) -> Finding:
    finding_id = uuid.uuid4()
    nonce = secrets.token_bytes(12)
    return Finding(
        id=finding_id,
        password_nonce=nonce,
        password_ciphertext=AESGCM(_OLD).encrypt(nonce, password, _finding_aad(finding_id)),
    )


def _setting(value: bytes) -> PlatformSetting:
    key = SettingKey.LEAKCHECK_API_KEY
    nonce = secrets.token_bytes(12)
    return PlatformSetting(
        key=key.value,
        schema_version=1,
        nonce=nonce,
        ciphertext=AESGCM(_OLD).encrypt(nonce, value, PlatformSettingsStore._aad(key, 1)),
    )


def _credential(secret: bytes) -> AdminCredential:
    user_id = uuid.uuid4()
    nonce = secrets.token_bytes(12)
    return AdminCredential(
        user_id=user_id,
        totp_secret_enc=nonce + AESGCM(_OLD).encrypt(nonce, secret, _totp_aad(user_id)),
    )


@pytest.mark.anyio
async def test_rotation_preserves_every_plaintext_under_the_new_key() -> None:
    finding = _finding(b"hunter2-fixture")
    setting = _setting(b"enterprise-key-fixture")
    credential = _credential(b"JBSWY3DPEHPK3PXP")
    db = _RotationSession([finding], [setting], [credential])

    report = await rotate(db, old_key=_OLD, new_key=_NEW)  # type: ignore[arg-type]

    assert report.failures == []
    assert (report.findings, report.settings, report.totp_secrets) == (1, 1, 1)

    new = AESGCM(_NEW)
    assert finding.password_nonce is not None and finding.password_ciphertext is not None
    assert (
        new.decrypt(finding.password_nonce, finding.password_ciphertext, _finding_aad(finding.id))
        == b"hunter2-fixture"
    )
    assert (
        new.decrypt(
            setting.nonce,
            setting.ciphertext,
            PlatformSettingsStore._aad(SettingKey.LEAKCHECK_API_KEY, 1),
        )
        == b"enterprise-key-fixture"
    )
    blob = credential.totp_secret_enc
    assert blob is not None
    assert new.decrypt(blob[:12], blob[12:], _totp_aad(credential.user_id)) == b"JBSWY3DPEHPK3PXP"


@pytest.mark.anyio
async def test_rotation_reports_undecryptable_rows_instead_of_destroying_them() -> None:
    """A wrong current key must be reported, never written over good ciphertext."""

    finding = _finding(b"hunter2-fixture")
    original = finding.password_ciphertext
    db = _RotationSession([finding], [], [])

    report = await rotate(db, old_key=secrets.token_bytes(32), new_key=_NEW)  # type: ignore[arg-type]

    assert report.findings == 0
    assert report.failures == [f"finding:{finding.id}"]
    assert finding.password_ciphertext == original


def test_decode_key_rejects_keys_that_are_not_256_bit() -> None:
    assert len(decode_key(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())) == 32
    with pytest.raises(ValueError, match="32 bytes"):
        decode_key(base64.urlsafe_b64encode(secrets.token_bytes(16)).decode())
