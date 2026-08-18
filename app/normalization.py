"""Total, kind-specific normalization for scan subjects and finding identities."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.models import SubjectKind

_PHONE = re.compile(r"^\+[1-9][0-9]{7,14}$")


class NormalizationError(ValueError):
    """A supplied subject cannot be represented canonically and safely."""


@dataclass(frozen=True, slots=True)
class NormalizedSubject:
    kind: SubjectKind
    value_norm: str
    value_display: str


def normalize_subject(kind: SubjectKind, value: str) -> NormalizedSubject:
    """Normalize a subject while preventing cleartext password persistence."""

    if kind is SubjectKind.PASSWORD:
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
            raise NormalizationError("password must contain between 1 and 4096 UTF-8 bytes")
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return NormalizedSubject(kind, digest, f"sha256:{digest[:12]}…")
    value = _text(value)
    if kind is SubjectKind.EMAIL:
        normalized = normalize_email(value)
        return NormalizedSubject(kind, normalized, normalized)
    if kind is SubjectKind.DOMAIN:
        normalized = normalize_domain(value)
        return NormalizedSubject(kind, normalized, normalized)
    if kind is SubjectKind.PHONE:
        normalized = normalize_phone(value)
        return NormalizedSubject(kind, normalized, normalized)
    if kind is SubjectKind.USERNAME:
        normalized = _bounded(value.casefold(), maximum=1024)
        return NormalizedSubject(kind, normalized, value)
    if kind is SubjectKind.ORIGIN:
        normalized = normalize_origin(value)
        return NormalizedSubject(kind, normalized, normalized)
    raise NormalizationError("unsupported subject kind")


def normalize_email(value: str) -> str:
    value = _bounded(_text(value).casefold(), maximum=320)
    if value.count("@") != 1:
        raise NormalizationError("email must contain one @")
    local, domain = value.rsplit("@", maxsplit=1)
    if not local or any(character.isspace() for character in local):
        raise NormalizationError("email local part is invalid")
    return f"{local}@{normalize_domain(domain)}"


def normalize_domain(value: str) -> str:
    domain = _text(value).casefold().rstrip(".")
    try:
        normalized = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalizationError("domain is invalid") from exc
    labels = normalized.split(".")
    if (
        len(normalized) > 253
        or len(labels) < 2
        or any(not label or len(label) > 63 for label in labels)
        or any(label.startswith("-") or label.endswith("-") for label in labels)
        or any(
            not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
    ):
        raise NormalizationError("domain is invalid")
    return normalized


def normalize_phone(value: str) -> str:
    compact = re.sub(r"[\s().-]", "", _text(value))
    if _PHONE.fullmatch(compact) is None:
        raise NormalizationError("phone must be an E.164 number including country code")
    return compact


def normalize_origin(value: str) -> str:
    raw = _bounded(_text(value), maximum=4096)
    if "://" not in raw:
        return raw.casefold()
    try:
        parsed = urlsplit(raw)
        hostname = normalize_domain(parsed.hostname or "")
        port = parsed.port
    except (ValueError, NormalizationError) as exc:
        raise NormalizationError("origin URL is invalid") from exc
    scheme = parsed.scheme.casefold()
    if (
        scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise NormalizationError("origin URL is invalid")
    include_port = port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    )
    netloc = f"{hostname}:{port}" if include_port else hostname
    return urlunsplit((scheme, netloc, parsed.path or "", parsed.query, ""))


def normalize_optional_email(value: str | None) -> str:
    if not value:
        return ""
    try:
        return normalize_email(value)
    except NormalizationError:
        # Historical vendor rows are not guaranteed to remain valid deliverable addresses.
        return _bounded(_text(value).casefold(), maximum=320)


def normalize_optional_username(value: str | None) -> str:
    return _bounded(_text(value).casefold(), maximum=1024) if value else ""


def normalize_optional_phone(value: str | None) -> str:
    if not value:
        return ""
    try:
        return normalize_phone(value)
    except NormalizationError:
        # Vendor data can contain historical non-E.164 values; retain a deterministic identity.
        return _bounded(_text(value).casefold(), maximum=64)


def _text(value: str) -> str:
    if not isinstance(value, str):
        raise NormalizationError("value must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or any(not character.isprintable() for character in normalized):
        raise NormalizationError("value must be non-empty printable text")
    return normalized


def _bounded(value: str, *, maximum: int) -> str:
    if len(value) > maximum:
        raise NormalizationError("value is too long")
    return value
