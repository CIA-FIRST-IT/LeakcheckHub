"""Subject normalization and finding-bound credential crypto tests."""

from __future__ import annotations

import base64
import hashlib
import uuid

import pytest

from app.config import Settings
from app.finding_crypto import (
    FindingCryptoError,
    mask_password,
    password_charset,
    protect_password,
    reveal_password,
)
from app.models import SubjectKind
from app.normalization import NormalizationError, normalize_subject


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("testserver",),
    )


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (SubjectKind.EMAIL, "  Alice@EXAMPLE.TEST ", "alice@example.test"),
        (SubjectKind.DOMAIN, "BÜCHER.Example.", "xn--bcher-kva.example"),
        (SubjectKind.PHONE, "+855 (12) 345-678", "+85512345678"),
        (SubjectKind.USERNAME, "  Ａlice  ", "alice"),
        (SubjectKind.ORIGIN, "HTTPS://Example.Test:443/path#fragment", "https://example.test/path"),
    ],
)
def test_subject_normalization_is_kind_specific(
    kind: SubjectKind, value: str, expected: str
) -> None:
    assert normalize_subject(kind, value).value_norm == expected


def test_password_subject_persists_only_a_digest_and_nonsecret_display() -> None:
    password = "correct horse battery staple"  # noqa: S105 - synthetic fixture
    normalized = normalize_subject(SubjectKind.PASSWORD, password)

    assert password not in normalized.value_norm
    assert password not in normalized.value_display
    assert len(normalized.value_norm) == 64


def test_password_subject_hashes_the_exact_unmodified_value() -> None:
    password = " leading and trailing \n"  # noqa: S105 - synthetic fixture

    normalized = normalize_subject(SubjectKind.PASSWORD, password)

    assert normalized.value_norm == hashlib.sha256(password.encode()).hexdigest()


@pytest.mark.parametrize("value", ["example", "+012345678", "not a phone"])
def test_invalid_e164_phone_is_rejected(value: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_subject(SubjectKind.PHONE, value)


def test_password_crypto_round_trip_mask_metadata_and_aad_tamper() -> None:
    settings = make_settings()
    finding_id = uuid.uuid4()
    password = "Pa$$word3"  # noqa: S105 - synthetic fixture
    protected = protect_password(settings, finding_id=finding_id, password=password)

    assert protected.ciphertext != password.encode()
    assert protected.mask == "Pa••••••3"
    assert protected.length == 9
    assert protected.charset == "lower+upper+digits+symbols"
    assert (
        reveal_password(
            settings,
            finding_id=finding_id,
            ciphertext=protected.ciphertext,
            nonce=protected.nonce,
        )
        == password
    )
    with pytest.raises(FindingCryptoError):
        reveal_password(
            settings,
            finding_id=uuid.uuid4(),
            ciphertext=protected.ciphertext,
            nonce=protected.nonce,
        )
    with pytest.raises(FindingCryptoError):
        reveal_password(
            settings,
            finding_id=finding_id,
            ciphertext=protected.ciphertext[:-1] + b"x",
            nonce=protected.nonce,
        )


def test_short_password_mask_reveals_only_the_first_character() -> None:
    assert mask_password("abcde") == "a••••"
    assert password_charset("1234") == "digits"
