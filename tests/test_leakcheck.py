"""Offline contract and failure-mode tests for the LeakCheck client."""

from __future__ import annotations

import json
from collections.abc import Callable
from unittest.mock import AsyncMock

import httpx
import pytest

from app.leakcheck import (
    LeakCheckClient,
    LeakCheckConfigurationError,
    LeakCheckProtocolError,
    LeakCheckResponseTooLarge,
    LeakCheckUnavailable,
    QueryType,
)


def response_payload(records: list[dict[str, object]], *, quota: int = 999_999) -> bytes:
    return json.dumps(
        {"success": True, "quota": quota, "found": len(records), "result": records}
    ).encode()


def sample_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "email": "person@example.test",
        "password": "example-password",
        "fields": ["email", "password"],
        "source": {"name": "Example", "breach_date": None},
    }
    record.update(overrides)
    return record


def mock_client(
    handler: Callable[[httpx.Request], httpx.Response], **kwargs: object
) -> tuple[LeakCheckClient, httpx.AsyncClient]:
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = LeakCheckClient(
        "configured-key",
        requests_per_second=10_000,
        http_client=http_client,
        **kwargs,
    )
    return client, http_client


@pytest.mark.anyio
@pytest.mark.parametrize("query_type", list(QueryType))
async def test_all_six_query_types_are_explicit_and_parse_offline(query_type: QueryType) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=response_payload([sample_record()]))

    client, http_client = mock_client(handler)
    try:
        result = await client.query(query_type, "person@example.test")
    finally:
        await http_client.aclose()

    assert result.query_type is query_type
    assert result.quota == 999_999
    assert len(result.records) == 1
    assert requests[0].url.params["type"] == query_type.value
    assert requests[0].headers["X-API-Key"] == "configured-key"


@pytest.mark.anyio
async def test_email_query_can_never_send_limit_or_offset() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=response_payload([]))

    client, http_client = mock_client(handler)
    try:
        await client.query(QueryType.EMAIL, "breached@example.test")
    finally:
        await http_client.aclose()

    assert len(requests) == 1
    assert set(requests[0].url.params.keys()) == {"type"}
    assert "offset" not in str(requests[0].url)


@pytest.mark.anyio
async def test_domain_pages_until_a_short_page_without_trusting_found() -> None:
    requests: list[httpx.Request] = []
    large_page = [sample_record(password=None) for _ in range(1000)]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        records = large_page if request.url.params["offset"] == "0" else [sample_record()]
        # found deliberately remains page-local, matching the measured API behaviour.
        return httpx.Response(200, content=response_payload(records))

    client, http_client = mock_client(handler)
    try:
        result = await client.query(QueryType.DOMAIN, "example.test")
    finally:
        await http_client.aclose()

    assert len(result.records) == 1001
    assert result.found == 1001
    assert result.truncated is False
    assert [request.url.params["offset"] for request in requests] == ["0", "1000"]
    assert all(request.url.params["limit"] == "1000" for request in requests)


@pytest.mark.anyio
async def test_tolerant_source_parser_retains_the_full_raw_record() -> None:
    raw = {
        "email": "x@example.test",
        "origin": ["bill24.net", "login.bill24.net"],
        "source": {"name": "Unknown"},
        "vendor_extra": {"x": 1},
    }
    client, http_client = mock_client(
        lambda _: httpx.Response(200, content=response_payload([raw]))
    )
    try:
        record = (await client.query(QueryType.EMAIL, "x@example.test")).records[0]
    finally:
        await http_client.aclose()

    assert record.source.name == "Unknown"
    assert record.source.breach_date is None
    assert record.source.passwordless is None
    assert record.origin == "bill24.net, login.bill24.net"
    assert record.raw == raw


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, LeakCheckConfigurationError),
        (400, LeakCheckProtocolError),
        (429, LeakCheckUnavailable),
    ],
)
async def test_measured_error_statuses_map_to_safe_client_errors(
    status: int, error_type: type[Exception]
) -> None:
    client, http_client = mock_client(
        lambda _: httpx.Response(status, json={"success": False, "error": "vendor detail"}),
        max_retries=0,
    )
    try:
        with pytest.raises(error_type):
            await client.query(QueryType.EMAIL, "x@example.test")
    finally:
        await http_client.aclose()


@pytest.mark.anyio
async def test_malformed_and_unsuccessful_bodies_fail_loudly() -> None:
    bodies = [b"not-json", b'{"success":false,"result":[]}']
    for body in bodies:
        client, http_client = mock_client(lambda _, body=body: httpx.Response(200, content=body))
        try:
            with pytest.raises(LeakCheckProtocolError):
                await client.query(QueryType.EMAIL, "x@example.test")
        finally:
            await http_client.aclose()


@pytest.mark.anyio
async def test_declared_and_streamed_oversized_bodies_are_rejected() -> None:
    handlers = [
        lambda _: httpx.Response(200, headers={"Content-Length": "100"}, content=b"{}"),
        lambda _: httpx.Response(200, content=b"x" * 20),
    ]
    for handler in handlers:
        client, http_client = mock_client(handler, max_response_bytes=10)
        try:
            with pytest.raises(LeakCheckResponseTooLarge):
                await client.query(QueryType.EMAIL, "x@example.test")
        finally:
            await http_client.aclose()


@pytest.mark.anyio
async def test_domain_marks_a_bounded_scan_truncated() -> None:
    page = [sample_record() for _ in range(1000)]
    client, http_client = mock_client(
        lambda _: httpx.Response(200, content=response_payload(page)), max_domain_pages=1
    )
    try:
        result = await client.query(QueryType.DOMAIN, "example.test")
    finally:
        await http_client.aclose()
    assert result.truncated is True


@pytest.mark.anyio
async def test_429_is_retried_as_a_backstop_after_self_pacing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, json={"success": False, "error": "rate limited"})
        return httpx.Response(200, content=response_payload([]))

    sleep = AsyncMock()
    monkeypatch.setattr("app.leakcheck.anyio.sleep", sleep)
    client, http_client = mock_client(handler, max_retries=1)
    try:
        result = await client.query(QueryType.EMAIL, "x@example.test")
    finally:
        await http_client.aclose()

    assert result.records == ()
    assert attempts == 2
    sleep.assert_awaited_once_with(1)


@pytest.mark.anyio
async def test_circuit_breaker_fails_fast_after_repeated_service_failure() -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, json={"success": False})

    client, http_client = mock_client(
        handler, max_retries=0, circuit_failure_threshold=1, circuit_reset_seconds=60
    )
    try:
        with pytest.raises(LeakCheckUnavailable):
            await client.query(QueryType.EMAIL, "x@example.test")
        with pytest.raises(LeakCheckUnavailable, match="circuit breaker"):
            await client.query(QueryType.EMAIL, "y@example.test")
    finally:
        await http_client.aclose()

    assert attempts == 1
