"""Google OpenID Connect authorization-code flow with PKCE and local JWT verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, TypeGuard, cast
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import User, UserRole, UserSource

GOOGLE_DISCOVERY_URL: Final = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_ISSUERS: Final = frozenset({"https://accounts.google.com", "accounts.google.com"})
GOOGLE_ENDPOINT_HOSTS: Final = frozenset(
    {"accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"}
)
OAUTH_TRANSACTION_COOKIE_NAME: Final = "__Host-leakcheck-oidc"
OAUTH_TRANSACTION_TTL: Final = timedelta(minutes=10)
_ID_TOKEN_MAX_LENGTH: Final = 16 * 1024
_CACHE_CONTROL_MAX_AGE: Final = re.compile(r"(?:^|,)\s*max-age=(\d+)\s*(?:,|$)", re.IGNORECASE)


class GoogleOIDCError(Exception):
    """A deliberately non-sensitive Google authentication failure."""


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The small, validated subset of Google's discovery document that this app uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str

    @classmethod
    def from_payload(cls, payload: object) -> ProviderMetadata:
        if not isinstance(payload, dict):
            raise GoogleOIDCError
        values = {key: payload.get(key) for key in cls.__dataclass_fields__}
        if not all(isinstance(value, str) for value in values.values()):
            raise GoogleOIDCError
        metadata = cls(**values)  # type: ignore[arg-type]
        if metadata.issuer not in GOOGLE_ISSUERS or any(
            not _trusted_google_endpoint(endpoint)
            for endpoint in (
                metadata.authorization_endpoint,
                metadata.token_endpoint,
                metadata.jwks_uri,
            )
        ):
            raise GoogleOIDCError
        return metadata


@dataclass(frozen=True, slots=True)
class GoogleIdentity:
    """The constrained identity claims the portal accepts from a verified ID token."""

    subject: str
    email: str
    display_name: str
    hosted_domain: str


@dataclass(frozen=True, slots=True)
class OAuthTransaction:
    """Short-lived, signed browser state for one authorization-code exchange."""

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    expires_at: int

    @classmethod
    def create(cls, *, now: datetime | None = None) -> OAuthTransaction:
        current = _utc_now(now)
        return cls(
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(64),
            expires_at=int((current + OAUTH_TRANSACTION_TTL).timestamp()),
        )

    @property
    def code_challenge(self) -> str:
        digest = hashlib.sha256(self.code_verifier.encode("ascii")).digest()
        return _base64url(digest)

    def serialize(self, key: bytes) -> str:
        """Serialise a signed state cookie without exposing it through logs or URLs."""

        payload = json.dumps(
            {
                "code_verifier": self.code_verifier,
                "expires_at": self.expires_at,
                "nonce": self.nonce,
                "state": self.state,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        encoded = _base64url(payload)
        signature = hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest()
        return f"{encoded}.{_base64url(signature)}"

    @classmethod
    def deserialize(
        cls, value: str | None, key: bytes, *, now: datetime | None = None
    ) -> OAuthTransaction | None:
        """Verify and parse a transaction cookie, rejecting tampering and expiry."""

        if value is None or value.count(".") != 1 or len(value) > 2048:
            return None
        encoded, supplied_signature = value.split(".", maxsplit=1)
        if not encoded.isascii() or not supplied_signature.isascii():
            return None
        expected_signature = _base64url(
            hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None
        try:
            payload = json.loads(_base64url_decode(encoded))
            transaction = cls(
                state=payload["state"],
                nonce=payload["nonce"],
                code_verifier=payload["code_verifier"],
                expires_at=payload["expires_at"],
            )
        except (binascii.Error, KeyError, TypeError, ValueError, UnicodeDecodeError):
            return None
        if (
            not all(
                isinstance(value, str)
                for value in (transaction.state, transaction.nonce, transaction.code_verifier)
            )
            or not isinstance(transaction.expires_at, int)
            or not _is_urlsafe_token(transaction.state, 43)
            or not _is_urlsafe_token(transaction.nonce, 43)
            or not _is_urlsafe_token(transaction.code_verifier, 86)
            or int(_utc_now(now).timestamp()) >= transaction.expires_at
        ):
            return None
        return transaction


class GoogleOIDC:
    """Perform OIDC exchanges and verify claims locally against Google JWKS keys."""

    def __init__(self, settings: Settings, *, http_client: httpx.AsyncClient | None = None) -> None:
        self._client_id = settings.google_client_id
        self._client_secret = settings.google_client_secret.get_secret_value()
        self._redirect_uri = settings.google_redirect_uri
        self._allowed_domains = frozenset(settings.google_workspace_domains)
        self._transaction_key = hmac.new(
            settings.session_secret.get_secret_value().encode("utf-8"),
            b"leakcheck/google-oidc-transaction/v1",
            hashlib.sha256,
        ).digest()
        self._http_client = http_client
        self._metadata_cache: tuple[ProviderMetadata, datetime] | None = None
        self._jwks_cache: tuple[dict[str, dict[str, object]], datetime] | None = None

    def begin_transaction(self, *, now: datetime | None = None) -> OAuthTransaction:
        """Create state, nonce, and verifier for a fresh login attempt."""

        return OAuthTransaction.create(now=now)

    def transaction_cookie(self, transaction: OAuthTransaction) -> str:
        """Return the authenticated transaction cookie value."""

        return transaction.serialize(self._transaction_key)

    def read_transaction_cookie(
        self, value: str | None, *, now: datetime | None = None
    ) -> OAuthTransaction | None:
        """Return a valid short-lived transaction from the callback request cookie."""

        return OAuthTransaction.deserialize(value, self._transaction_key, now=now)

    async def authorization_url(self, transaction: OAuthTransaction) -> str:
        """Build a code-only Google authorization URL with S256 PKCE."""

        metadata = await self._metadata()
        parameters = {
            "client_id": self._client_id,
            "code_challenge": transaction.code_challenge,
            "code_challenge_method": "S256",
            "nonce": transaction.nonce,
            "redirect_uri": self._redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": transaction.state,
        }
        if len(self._allowed_domains) == 1:
            parameters["hd"] = next(iter(self._allowed_domains))
        return f"{metadata.authorization_endpoint}?{urlencode(parameters)}"

    async def exchange_and_verify(self, code: str, transaction: OAuthTransaction) -> GoogleIdentity:
        """Exchange one code and validate every identity-bearing ID token claim locally."""

        if not code or len(code) > 2048:
            raise GoogleOIDCError
        metadata = await self._metadata()
        payload = await self._token_exchange(metadata, code, transaction.code_verifier)
        id_token = payload.get("id_token") if isinstance(payload, dict) else None
        if not isinstance(id_token, str) or not id_token or len(id_token) > _ID_TOKEN_MAX_LENGTH:
            raise GoogleOIDCError
        claims = await self._verify_id_token(metadata, id_token, transaction.nonce)
        return self._identity_from_claims(claims)

    async def _metadata(self) -> ProviderMetadata:
        current = datetime.now(UTC)
        if self._metadata_cache is not None and current < self._metadata_cache[1]:
            return self._metadata_cache[0]
        response = await self._request("GET", GOOGLE_DISCOVERY_URL)
        payload = _json_payload(response)
        metadata = ProviderMetadata.from_payload(payload)
        self._metadata_cache = (metadata, _cache_expiry(response, default_seconds=3600))
        return metadata

    async def _token_exchange(
        self, metadata: ProviderMetadata, code: str, code_verifier: str
    ) -> dict[str, object]:
        response = await self._request(
            "POST",
            metadata.token_endpoint,
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": self._redirect_uri,
            },
        )
        payload = _json_payload(response)
        if not isinstance(payload, dict):
            raise GoogleOIDCError
        return payload

    async def _verify_id_token(
        self, metadata: ProviderMetadata, id_token: str, nonce: str
    ) -> dict[str, object]:
        try:
            header = jwt.get_unverified_header(id_token)
        except InvalidTokenError as exc:
            raise GoogleOIDCError from exc
        kid = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid or len(kid) > 128:
            raise GoogleOIDCError

        jwk = await self._find_jwk(kid)
        try:
            public_key = cast(RSAPublicKey, RSAAlgorithm.from_jwk(json.dumps(jwk)))
            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=GOOGLE_ISSUERS,
                leeway=60,
                options={"require": ["aud", "exp", "iss", "nonce", "sub"]},
            )
        except (InvalidTokenError, ValueError, TypeError) as exc:
            raise GoogleOIDCError from exc
        token_nonce = claims.get("nonce") if isinstance(claims, dict) else None
        if (
            not isinstance(token_nonce, str)
            or not token_nonce.isascii()
            or not hmac.compare_digest(token_nonce, nonce)
        ):
            raise GoogleOIDCError

        audiences = claims.get("aud")
        if isinstance(audiences, list) and (
            not isinstance(claims.get("azp"), str)
            or not hmac.compare_digest(claims["azp"], self._client_id)
        ):
            raise GoogleOIDCError
        return claims

    async def _find_jwk(self, kid: str) -> dict[str, object]:
        keys = await self._jwks()
        key = keys.get(kid)
        if key is None:
            self._jwks_cache = None
            key = (await self._jwks()).get(kid)
        if key is None:
            raise GoogleOIDCError
        return key

    async def _jwks(self) -> dict[str, dict[str, object]]:
        current = datetime.now(UTC)
        if self._jwks_cache is not None and current < self._jwks_cache[1]:
            return self._jwks_cache[0]
        metadata = await self._metadata()
        response = await self._request("GET", metadata.jwks_uri)
        payload = _json_payload(response)
        if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
            raise GoogleOIDCError
        keys: dict[str, dict[str, object]] = {}
        for value in payload["keys"]:
            if (
                isinstance(value, dict)
                and isinstance(value.get("kid"), str)
                and value.get("kty") == "RSA"
                and value.get("use") == "sig"
                and value.get("alg") == "RS256"
            ):
                keys[value["kid"]] = value
        if not keys:
            raise GoogleOIDCError
        self._jwks_cache = (keys, _cache_expiry(response, default_seconds=300))
        return keys

    def _identity_from_claims(self, claims: dict[str, object]) -> GoogleIdentity:
        subject = claims.get("sub")
        email = claims.get("email")
        hosted_domain = claims.get("hd")
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 255
            or not _valid_email(email)
            or claims.get("email_verified") is not True
            or not isinstance(hosted_domain, str)
            or hosted_domain.casefold().rstrip(".") not in self._allowed_domains
        ):
            raise GoogleOIDCError
        verified_email = email
        display_name_claim = claims.get("name")
        display_name = (
            display_name_claim.strip()
            if isinstance(display_name_claim, str) and display_name_claim.strip()
            else verified_email.split("@", maxsplit=1)[0]
        )
        if len(display_name) > 255:
            raise GoogleOIDCError
        return GoogleIdentity(
            subject=subject,
            email=verified_email.casefold(),
            display_name=display_name,
            hosted_domain=hosted_domain.casefold().rstrip("."),
        )

    async def _request(
        self, method: str, url: str, *, data: dict[str, str] | None = None
    ) -> httpx.Response:
        try:
            if self._http_client is not None:
                response = await self._http_client.request(method, url, data=data)
            else:
                async with httpx.AsyncClient(
                    timeout=10.0, follow_redirects=False, trust_env=False
                ) as client:
                    response = await client.request(method, url, data=data)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise GoogleOIDCError from exc
        return response


async def provision_google_user(db: AsyncSession, identity: GoogleIdentity) -> User:
    """Link an existing identity or create a least-privilege user without altering their role."""

    subject_result = await db.execute(
        select(User).where(User.google_sub == identity.subject).with_for_update()
    )
    user = subject_result.scalar_one_or_none()
    email_result = await db.execute(
        select(User).where(User.email == identity.email).with_for_update()
    )
    email_user = email_result.scalar_one_or_none()

    if user is not None:
        if email_user is not None and email_user.id != user.id:
            raise GoogleOIDCError
        user.email = identity.email
        user.display_name = identity.display_name
    elif email_user is not None:
        if email_user.google_sub is not None and email_user.google_sub != identity.subject:
            raise GoogleOIDCError
        user = email_user
        user.google_sub = identity.subject
        user.display_name = identity.display_name
    else:
        user = User(
            id=uuid.uuid4(),
            email=identity.email,
            google_sub=identity.subject,
            display_name=identity.display_name,
            role=UserRole.USER,
            source=UserSource.GOOGLE,
        )
        db.add(user)
    await db.flush()
    return user


def _cache_expiry(response: httpx.Response, *, default_seconds: int) -> datetime:
    """Respect provider cache TTLs while bounding a compromised or malformed cache directive."""

    match = _CACHE_CONTROL_MAX_AGE.search(response.headers.get("cache-control", ""))
    seconds = int(match.group(1)) if match is not None else default_seconds
    return datetime.now(UTC) + timedelta(seconds=min(max(seconds, 0), 24 * 60 * 60))


def _json_payload(response: httpx.Response) -> object:
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise GoogleOIDCError from exc


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _is_urlsafe_token(value: str, expected_length: int) -> bool:
    return len(value) == expected_length and all(
        character.isascii() and (character.isalnum() or character in "-_") for character in value
    )


def _trusted_google_endpoint(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in GOOGLE_ENDPOINT_HOSTS
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def _valid_email(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 320
        and value.count("@") == 1
        and all(not character.isspace() and character.isprintable() for character in value)
    )


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("OIDC timestamps must be timezone-aware")
    return current.astimezone(UTC)
