"""AES-256-GCM credential encryption, masking, and metadata derivation."""

from __future__ import annotations

import base64
import hashlib
import secrets
import unicodedata
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Settings

_NONCE_BYTES = 12


class FindingCryptoError(Exception):
    """Credential ciphertext is malformed, relocated, or encrypted under another key."""


@dataclass(frozen=True, slots=True)
class ProtectedPassword:
    ciphertext: bytes
    nonce: bytes
    sha256: bytes
    mask: str
    length: int
    charset: str


def protect_password(
    settings: Settings, *, finding_id: uuid.UUID, password: str
) -> ProtectedPassword:
    """Derive non-secret metadata and encrypt one password with finding-bound AAD."""

    plaintext = password.encode("utf-8")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = AESGCM(_key(settings)).encrypt(nonce, plaintext, _aad(finding_id))
    return ProtectedPassword(
        ciphertext=ciphertext,
        nonce=nonce,
        sha256=hashlib.sha256(plaintext).digest(),
        mask=mask_password(password),
        length=len(password),
        charset=password_charset(password),
    )


def reveal_password(
    settings: Settings, *, finding_id: uuid.UUID, ciphertext: bytes, nonce: bytes
) -> str:
    """Decrypt only for the explicit analyst reveal path, rejecting AAD relocation."""

    if len(nonce) != _NONCE_BYTES:
        raise FindingCryptoError("invalid password nonce")
    try:
        return AESGCM(_key(settings)).decrypt(nonce, ciphertext, _aad(finding_id)).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise FindingCryptoError("password ciphertext authentication failed") from exc


def mask_password(password: str) -> str:
    if not password:
        return ""
    if len(password) < 6:
        return _safe_mask_character(password[0]) + ("•" * (len(password) - 1))
    return (
        "".join(_safe_mask_character(character) for character in password[:2])
        + ("•" * (len(password) - 3))
        + _safe_mask_character(password[-1])
    )


def password_charset(password: str) -> str:
    classes: list[str] = []
    if any(character.islower() for character in password):
        classes.append("lower")
    if any(character.isupper() for character in password):
        classes.append("upper")
    if any(character.isdigit() for character in password):
        classes.append("digits")
    if any(unicodedata.category(character).startswith(("P", "S")) for character in password):
        classes.append("symbols")
    if any(not character.isascii() for character in password):
        classes.append("unicode")
    return "+".join(classes) or "other"


def _key(settings: Settings) -> bytes:
    encoded = settings.data_key.get_secret_value()
    return base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))


def _aad(finding_id: uuid.UUID) -> bytes:
    return b"leakcheck/finding-password/v1\x00" + finding_id.bytes


def _safe_mask_character(character: str) -> str:
    return character if character.isprintable() and not character.isspace() else "•"
