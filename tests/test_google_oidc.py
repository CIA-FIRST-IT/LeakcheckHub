"""Offline verification for the Google authorization-code and provisioning flow."""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.google import (
    GOOGLE_DISCOVERY_URL,
    OAUTH_TRANSACTION_COOKIE_NAME,
    GoogleIdentity,
    GoogleOIDC,
    GoogleOIDCError,
    ProviderMetadata,
    provision_google_user,
)
from app.config import Settings
from app.db import get_db_session
from app.main import create_app
from app.models import User, UserRole, UserSource

NOW = datetime(2026, 8, 15, 12, tzinfo=UTC)
CLIENT_ID = "portal-client-id.apps.googleusercontent.com"


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://runtime:password@postgres/leakcheck",
        session_secret="s" * 32,
        google_client_id=CLIENT_ID,
        google_client_secret="c" * 32,
        google_redirect_uri="https://portal.example.test/auth/google/callback",
        google_workspace_domains=("example.test",),
        data_key=base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        trusted_hosts=("portal.example.test",),
    )


@dataclass
class ScalarResult:
    value: User | None

    def scalar_one_or_none(self) -> User | None:
        return self.value


@dataclass
class FakeAsyncSession:
    results: list[User | None]
    added: list[object] = field(default_factory=list)
    flush: AsyncMock = field(default_factory=AsyncMock)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def execute(self, statement: object) -> ScalarResult:
        del statement
        return ScalarResult(self.results.pop(0))


def _base64url_integer(value: int) -> str:
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwk(private_key: rsa.RSAPrivateKey) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "alg": "RS256",
        "e": _base64url_integer(numbers.e),
        "kid": "test-key",
        "kty": "RSA",
        "n": _base64url_integer(numbers.n),
        "use": "sig",
    }


def make_id_token(
    private_key: rsa.RSAPrivateKey,
    *,
    nonce: str,
    hosted_domain: str = "example.test",
) -> str:
    current = int(time.time())
    return jwt.encode(
        {
            "aud": CLIENT_ID,
            "email": "member@example.test",
            "email_verified": True,
            "exp": current + 3600,
            "hd": hosted_domain,
            "iat": current,
            "iss": "https://accounts.google.com",
            "name": "Portal Member",
            "nonce": nonce,
            "sub": "google-subject-123",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def oidc_transport(
    *, id_token: str, expected_code_verifier: str, jwk: dict[str, str]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GOOGLE_DISCOVERY_URL:
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                    "issuer": "https://accounts.google.com",
                    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                    "token_endpoint": "https://oauth2.googleapis.com/token",
                },
                headers={"Cache-Control": "max-age=600"},
                request=request,
            )
        if str(request.url) == "https://oauth2.googleapis.com/token":
            form = parse_qs(request.content.decode("ascii"))
            assert form["code"] == ["one-time-code"]
            assert form["code_verifier"] == [expected_code_verifier]
            assert form["grant_type"] == ["authorization_code"]
            assert form["redirect_uri"] == ["https://portal.example.test/auth/google/callback"]
            return httpx.Response(200, json={"id_token": id_token}, request=request)
        if str(request.url) == "https://www.googleapis.com/oauth2/v3/certs":
            return httpx.Response(
                200,
                json={"keys": [jwk]},
                headers={"Cache-Control": "max-age=600"},
                request=request,
            )
        raise AssertionError(f"unexpected outbound request: {request.url}")

    return httpx.MockTransport(handler)


def test_transaction_cookie_is_signed_expiring_and_not_repr_safe() -> None:
    oidc = GoogleOIDC(make_settings())
    transaction = oidc.begin_transaction(now=NOW)
    cookie = oidc.transaction_cookie(transaction)

    assert transaction.state not in repr(transaction)
    assert transaction.nonce not in repr(transaction)
    assert transaction.code_verifier not in repr(transaction)
    assert oidc.read_transaction_cookie(cookie, now=NOW) == transaction
    assert oidc.read_transaction_cookie(f"{cookie[:-1]}x", now=NOW) is None
    assert oidc.read_transaction_cookie("é.invalid", now=NOW) is None
    assert oidc.read_transaction_cookie(cookie, now=NOW + timedelta(minutes=10)) is None


def test_discovery_metadata_cannot_redirect_authentication_to_a_non_google_host() -> None:
    with pytest.raises(GoogleOIDCError):
        ProviderMetadata.from_payload(
            {
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "issuer": "https://accounts.google.com",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "token_endpoint": "https://attacker.example/token",
            }
        )


@pytest.mark.anyio
async def test_authorization_url_uses_only_code_flow_s256_pkce_and_a_domain_hint() -> None:
    unused_value = "unused"
    async with httpx.AsyncClient(
        transport=oidc_transport(
            id_token=unused_value,
            expected_code_verifier=unused_value,
            jwk={"alg": "RS256", "kid": "unused", "kty": "RSA", "use": "sig"},
        )
    ) as client:
        oidc = GoogleOIDC(make_settings(), http_client=client)
        transaction = oidc.begin_transaction(now=NOW)
        url = await oidc.authorization_url(transaction)

    parsed = urlsplit(url)
    parameters = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    assert parameters["response_type"] == ["code"]
    assert parameters["code_challenge_method"] == ["S256"]
    assert parameters["code_challenge"] == [transaction.code_challenge]
    assert parameters["state"] == [transaction.state]
    assert parameters["nonce"] == [transaction.nonce]
    assert parameters["hd"] == ["example.test"]
    assert "id_token" not in parameters.get("response_type", [])


@pytest.mark.anyio
async def test_exchange_verifies_the_jwks_signature_and_required_claims_locally() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transaction = GoogleOIDC(make_settings()).begin_transaction(now=NOW)
    id_token = make_id_token(private_key, nonce=transaction.nonce)
    async with httpx.AsyncClient(
        transport=oidc_transport(
            id_token=id_token,
            expected_code_verifier=transaction.code_verifier,
            jwk=make_jwk(private_key),
        )
    ) as client:
        oidc = GoogleOIDC(make_settings(), http_client=client)
        identity = await oidc.exchange_and_verify("one-time-code", transaction)

    assert identity == GoogleIdentity(
        subject="google-subject-123",
        email="member@example.test",
        display_name="Portal Member",
        hosted_domain="example.test",
    )


@pytest.mark.anyio
async def test_exchange_rejects_a_verified_token_from_an_unapproved_hosted_domain() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transaction = GoogleOIDC(make_settings()).begin_transaction(now=NOW)
    id_token = make_id_token(private_key, nonce=transaction.nonce, hosted_domain="attacker.example")
    async with httpx.AsyncClient(
        transport=oidc_transport(
            id_token=id_token,
            expected_code_verifier=transaction.code_verifier,
            jwk=make_jwk(private_key),
        )
    ) as client:
        oidc = GoogleOIDC(make_settings(), http_client=client)
        with pytest.raises(GoogleOIDCError):
            await oidc.exchange_and_verify("one-time-code", transaction)


@pytest.mark.anyio
async def test_auto_provision_creates_only_a_standard_google_user() -> None:
    db = FakeAsyncSession(results=[None, None])
    identity = GoogleIdentity(
        subject="google-subject-123",
        email="member@example.test",
        display_name="Portal Member",
        hosted_domain="example.test",
    )

    user = await provision_google_user(db, identity)  # type: ignore[arg-type]

    assert user in db.added
    assert user.role is UserRole.USER
    assert user.source is UserSource.GOOGLE
    assert user.google_sub == "google-subject-123"
    db.flush.assert_awaited_once()


@pytest.mark.anyio
async def test_auto_provision_links_a_manual_user_without_changing_their_role() -> None:
    existing = User(
        id=uuid.uuid4(),
        email="member@example.test",
        display_name="Old Name",
        role=UserRole.ANALYST,
        source=UserSource.MANUAL,
    )
    db = FakeAsyncSession(results=[None, existing])
    identity = GoogleIdentity(
        subject="google-subject-123",
        email="member@example.test",
        display_name="Portal Member",
        hosted_domain="example.test",
    )

    user = await provision_google_user(db, identity)  # type: ignore[arg-type]

    assert user is existing
    assert user.google_sub == identity.subject
    assert user.role is UserRole.ANALYST
    assert user.source is UserSource.MANUAL
    assert db.added == []


@pytest.mark.anyio
async def test_auto_provision_rejects_an_email_already_bound_to_another_google_subject() -> None:
    existing = User(
        id=uuid.uuid4(),
        email="member@example.test",
        google_sub="different-subject",
        display_name="Existing Member",
        source=UserSource.GOOGLE,
    )
    db = FakeAsyncSession(results=[None, existing])
    identity = GoogleIdentity(
        subject="google-subject-123",
        email="member@example.test",
        display_name="Portal Member",
        hosted_domain="example.test",
    )

    with pytest.raises(GoogleOIDCError):
        await provision_google_user(db, identity)  # type: ignore[arg-type]

    db.flush.assert_not_awaited()


@pytest.mark.anyio
async def test_login_route_sets_a_secure_signed_transaction_cookie() -> None:
    class FakeLoginOIDC:
        def __init__(self) -> None:
            self.transaction = GoogleOIDC(make_settings()).begin_transaction(now=NOW)

        def begin_transaction(self) -> object:
            return self.transaction

        async def authorization_url(self, transaction: object) -> str:
            assert transaction is self.transaction
            return "https://accounts.google.com/o/oauth2/v2/auth?response_type=code"

        def transaction_cookie(self, transaction: object) -> str:
            assert transaction is self.transaction
            return "signed-transaction"

    app = create_app(make_settings())
    app.state.google_oidc = FakeLoginOIDC()
    transport_to_app = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport_to_app,
        base_url="https://portal.example.test",
        follow_redirects=False,
    ) as client:
        response = await client.get("/auth/google/login")

    assert response.status_code == 303
    assert response.headers["location"].startswith("https://accounts.google.com/")
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{OAUTH_TRANSACTION_COOKIE_NAME}=")
    assert "HttpOnly" in cookie
    assert "Path=/" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" in cookie
    assert "Cache-Control" not in cookie
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.anyio
async def test_callback_rejects_non_ascii_state_without_calling_google() -> None:
    app = create_app(make_settings())
    transaction = app.state.google_oidc.begin_transaction()

    async def fake_db_dependency() -> object:
        yield object()

    app.dependency_overrides[get_db_session] = fake_db_dependency
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://portal.example.test",
        follow_redirects=False,
    ) as client:
        client.cookies.set(
            OAUTH_TRANSACTION_COOKIE_NAME,
            app.state.google_oidc.transaction_cookie(transaction),
            domain="portal.example.test",
            path="/",
        )
        response = await client.get("/auth/google/callback?code=one-time-code&state=%C3%A9")

    assert response.status_code == 400
    assert response.text == "Google authentication failed."
    assert f'{OAUTH_TRANSACTION_COOKIE_NAME}=""' in response.headers["set-cookie"]
