"""Offline tests for delegated read-only Directory access and safe sync statements."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.google_workspace import (
    ORGUNIT_READONLY,
    USER_READONLY,
    GoogleWorkspaceClient,
    WorkspaceAPIError,
    WorkspaceUser,
    sync_workspace_users,
)


def _decode(segment: str) -> dict[str, object]:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _credentials() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return json.dumps(
        {
            "client_email": "directory-reader@example-project.iam.gserviceaccount.com",
            "private_key": pem,
            "private_key_id": "temporary-test-key",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


@pytest.mark.anyio
async def test_directory_client_uses_exact_readonly_scopes_and_paginates() -> None:
    assertions: list[str] = []
    pages: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            form = parse_qs(request.content.decode())
            assertions.append(form["assertion"][0])
            return httpx.Response(200, json={"access_token": "short-lived", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer short-lived"
        if request.url.path.endswith("/orgunits"):
            assert request.url.params["type"] == "ALL"
            return httpx.Response(
                200, json={"organizationUnits": [{"name": "SOC", "orgUnitPath": "/SOC"}]}
            )
        pages.append(request.url.params.get("pageToken"))
        if len(pages) == 1:
            return httpx.Response(
                200,
                json={
                    "users": [
                        {
                            "id": "one",
                            "primaryEmail": "One@Example.com",
                            "name": {"fullName": "One User"},
                            "orgUnitPath": "/SOC",
                        }
                    ],
                    "nextPageToken": "next",
                },
            )
        return httpx.Response(
            200,
            json={
                "users": [
                    {
                        "id": "two",
                        "primaryEmail": "two@example.com",
                        "suspended": True,
                    }
                ]
            },
        )

    client = GoogleWorkspaceClient(
        _credentials(), "delegated-admin@example.com", transport=httpx.MockTransport(handler)
    )
    try:
        units = await client.list_org_units()
        users = await client.list_users()
    finally:
        await client.aclose()
    assert units[0].path == "/SOC"
    assert [user.email for user in users] == ["one@example.com", "two@example.com"]
    assert users[1].suspended is True
    assert pages == [None, "next"]
    assert len(assertions) == 1  # token is cached in process memory
    _, claims_segment, _ = assertions[0].split(".")
    claims = _decode(claims_segment)
    assert claims["sub"] == "delegated-admin@example.com"
    assert set(str(claims["scope"]).split()) == {USER_READONLY, ORGUNIT_READONLY}
    assert int(claims["exp"]) - int(claims["iat"]) == 3600


@pytest.mark.anyio
async def test_directory_error_never_exposes_remote_response_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "token"})
        return httpx.Response(403, text="private upstream diagnostic and token")

    client = GoogleWorkspaceClient(
        _credentials(), "admin@example.com", transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(WorkspaceAPIError, match="HTTP 403") as caught:
            await client.list_users()
    finally:
        await client.aclose()
    assert "private upstream" not in str(caught.value)


class _SyncResult:
    rowcount = 0


class _SyncDB:
    def __init__(self) -> None:
        self.statements: list[str] = []

    async def execute(self, statement: object) -> _SyncResult:
        self.statements.append(str(statement))
        return _SyncResult()

    async def flush(self) -> None:
        return None


@pytest.mark.anyio
async def test_sync_is_additive_idempotent_and_never_deletes() -> None:
    users = (WorkspaceUser("immutable-id", "person@example.com", "Person", "/SOC", False),)
    db = _SyncDB()
    first = await sync_workspace_users(db, users)  # type: ignore[arg-type]
    second = await sync_workspace_users(db, users)  # type: ignore[arg-type]
    sql = "\n".join(db.statements).upper()
    assert first.seen == second.seen == 1
    assert sql.count("ON CONFLICT") == 2
    assert "DELETE" not in sql
    assert "UPDATE USERS SET IS_ACTIVE" in sql
