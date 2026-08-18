"""Measured-contract LeakCheck Enterprise client.

Email and domain pagination deliberately have separate code paths. This prevents an email request
from ever acquiring an ``offset`` parameter, which the live API turns into a false negative.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from urllib.parse import quote

import anyio
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform_settings import PlatformSettingsStore, SettingKey

_BASE_URL: Final = "https://leakcheck.io/api/v2/query"
_DEFAULT_TIMEOUT_SECONDS: Final = 120.0
_DOMAIN_PAGE_SIZE: Final = 1000


class QueryType(StrEnum):
    EMAIL = "email"
    DOMAIN = "domain"
    USERNAME = "username"
    PHONE = "phone"
    ORIGIN = "origin"
    PASSWORD = "password"  # noqa: S105  # nosec B105


class LeakCheckError(Exception):
    """Base error exposed to scan orchestration."""


class LeakCheckConfigurationError(LeakCheckError):
    """The API key is absent or rejected."""


class LeakCheckProtocolError(LeakCheckError):
    """The service returned an invalid or contract-breaking response."""


class LeakCheckResponseTooLarge(LeakCheckError):
    """The response crossed the configured hard memory-safety limit."""


class LeakCheckUnavailable(LeakCheckError):
    """Retries or the local circuit breaker prevented a request."""


@dataclass(frozen=True, slots=True)
class BreachSource:
    name: str | None
    breach_date: str | None
    unverified: bool | None
    passwordless: bool | None
    compilation: bool | None


@dataclass(frozen=True, slots=True)
class LeakRecord:
    email: str | None
    username: str | None
    phone: str | None
    origin: str | None
    password: str | None
    fields: tuple[str, ...]
    source: BreachSource
    raw: dict[str, object]


@dataclass(frozen=True, slots=True)
class QueryResult:
    query_type: QueryType
    records: tuple[LeakRecord, ...]
    quota: int | None
    found: int
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _ParsedPage:
    records: tuple[LeakRecord, ...]
    quota: int | None
    found: int


class TokenBucket:
    """A monotonic, async token bucket that self-paces before every HTTP attempt."""

    def __init__(self, rate: float) -> None:
        if rate < 1:
            raise ValueError("rate must be at least one request per second")
        self._rate = rate
        # A capacity of one spaces starts evenly and cannot exceed three in any rolling second.
        self._capacity = 1.0
        self._tokens = 1.0
        self._updated_at: float | None = None
        self._lock = anyio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = anyio.current_time()
                if self._updated_at is None:
                    self._updated_at = now
                else:
                    elapsed = max(0.0, now - self._updated_at)
                    self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                    self._updated_at = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                delay = (1 - self._tokens) / self._rate
            await anyio.sleep(delay)


class LeakCheckClient:
    """Async LeakCheck client with hard bounds, retries, pacing, and a circuit breaker."""

    def __init__(
        self,
        api_key: str,
        *,
        requests_per_second: float = 3,
        concurrency: int = 3,
        max_response_bytes: int = 32 * 1024 * 1024,
        max_retries: int = 3,
        max_domain_pages: int = 100,
        circuit_failure_threshold: int = 5,
        circuit_reset_seconds: float = 30,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key or len(api_key) > 1024:
            raise LeakCheckConfigurationError("LeakCheck API key is not configured")
        if concurrency < 1 or max_response_bytes < 1 or max_retries < 0 or max_domain_pages < 1:
            raise ValueError("invalid LeakCheck client limits")
        self._api_key = api_key
        self._limiter = TokenBucket(requests_per_second)
        self._semaphore = anyio.Semaphore(concurrency)
        self._max_response_bytes = max_response_bytes
        self._max_retries = max_retries
        self._max_domain_pages = max_domain_pages
        self._circuit_failure_threshold = circuit_failure_threshold
        self._circuit_reset_seconds = circuit_reset_seconds
        self._circuit_failures = 0
        self._circuit_opened_at: float | None = None
        self._http_client = http_client

    async def query(self, query_type: QueryType, query: str) -> QueryResult:
        """Return all records under the measured per-type pagination contract."""

        if not query or len(query.encode("utf-8")) > 4096:
            raise ValueError("query must contain between 1 and 4096 UTF-8 bytes")
        if query_type is QueryType.DOMAIN:
            return await self._query_domain(query)
        # The EMAIL path can never receive caller parameters and therefore can never send offset.
        page = await self._request_page(query_type, query, parameters={})
        return QueryResult(
            query_type=query_type,
            records=page.records,
            quota=page.quota,
            found=page.found,
        )

    async def _query_domain(self, query: str) -> QueryResult:
        records: list[LeakRecord] = []
        quota: int | None = None
        found = 0
        for page_number in range(self._max_domain_pages):
            page = await self._request_page(
                QueryType.DOMAIN,
                query,
                parameters={
                    "limit": str(_DOMAIN_PAGE_SIZE),
                    "offset": str(page_number * _DOMAIN_PAGE_SIZE),
                },
            )
            records.extend(page.records)
            quota = page.quota
            found += len(page.records)
            if len(page.records) < _DOMAIN_PAGE_SIZE:
                return QueryResult(QueryType.DOMAIN, tuple(records), quota, found, truncated=False)
        return QueryResult(QueryType.DOMAIN, tuple(records), quota, found, truncated=True)

    async def _request_page(
        self, query_type: QueryType, query: str, *, parameters: dict[str, str]
    ) -> _ParsedPage:
        params = {"type": query_type.value, **parameters}
        url = f"{_BASE_URL}/{quote(query, safe='')}"
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            self._ensure_circuit_available()
            await self._limiter.acquire()
            try:
                async with self._semaphore:
                    status_code, body = await self._send(url, params)
            except (httpx.HTTPError, TimeoutError) as exc:
                last_error = exc
                self._record_failure()
                if attempt < self._max_retries:
                    await anyio.sleep(min(2**attempt, 8))
                    continue
                raise LeakCheckUnavailable("LeakCheck request failed") from exc

            if status_code == 401:
                self._record_success()
                raise LeakCheckConfigurationError("LeakCheck rejected the configured API key")
            if status_code == 400:
                self._record_success()
                raise LeakCheckProtocolError("LeakCheck rejected a client-generated request")
            if status_code == 429 or status_code >= 500:
                self._record_failure()
                if attempt < self._max_retries:
                    await anyio.sleep(min(2**attempt, 8))
                    continue
                raise LeakCheckUnavailable(f"LeakCheck remained unavailable (HTTP {status_code})")
            if status_code != 200:
                self._record_success()
                raise LeakCheckProtocolError(f"unexpected LeakCheck HTTP status {status_code}")
            self._record_success()
            return _parse_page(body)
        raise LeakCheckUnavailable("LeakCheck request failed") from last_error

    async def _send(self, url: str, params: dict[str, str]) -> tuple[int, bytes]:
        owns_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(_DEFAULT_TIMEOUT_SECONDS), follow_redirects=False, trust_env=False
        )
        try:
            request = client.build_request(
                "GET",
                url,
                params=params,
                headers={"X-API-Key": self._api_key, "Accept": "application/json"},
            )
            response = await client.send(request, stream=True)
            try:
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        if int(declared) > self._max_response_bytes:
                            raise LeakCheckResponseTooLarge(
                                "LeakCheck response exceeds configured limit"
                            )
                    except ValueError as exc:
                        raise LeakCheckProtocolError(
                            "LeakCheck returned an invalid Content-Length"
                        ) from exc
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise LeakCheckResponseTooLarge(
                            "LeakCheck response exceeds configured limit"
                        )
                return response.status_code, bytes(body)
            finally:
                await response.aclose()
        finally:
            if owns_client:
                await client.aclose()

    def _ensure_circuit_available(self) -> None:
        if self._circuit_opened_at is None:
            return
        now = anyio.current_time()
        if now - self._circuit_opened_at < self._circuit_reset_seconds:
            raise LeakCheckUnavailable("LeakCheck circuit breaker is open")
        self._circuit_opened_at = None
        self._circuit_failures = 0

    def _record_failure(self) -> None:
        self._circuit_failures += 1
        if self._circuit_failures >= self._circuit_failure_threshold:
            self._circuit_opened_at = anyio.current_time()

    def _record_success(self) -> None:
        self._circuit_failures = 0
        self._circuit_opened_at = None


async def client_from_platform_settings(
    db: AsyncSession,
    store: PlatformSettingsStore,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> LeakCheckClient:
    """Construct a client from the encrypted store, failing closed on a blank API key."""

    keys = {
        SettingKey.LEAKCHECK_API_KEY,
        SettingKey.LEAKCHECK_RPS,
        SettingKey.LEAKCHECK_CONCURRENCY,
        SettingKey.LEAKCHECK_MAX_RESPONSE_BYTES,
    }
    values = await store.read_many(db, keys)
    api_key = values.get(SettingKey.LEAKCHECK_API_KEY)
    if api_key is None:
        raise LeakCheckConfigurationError("LeakCheck API key is not configured")
    try:
        rps = float(values.get(SettingKey.LEAKCHECK_RPS, "3"))
        concurrency = int(values.get(SettingKey.LEAKCHECK_CONCURRENCY, "3"))
        max_bytes = int(values.get(SettingKey.LEAKCHECK_MAX_RESPONSE_BYTES, str(32 * 1024 * 1024)))
    except ValueError as exc:
        raise LeakCheckConfigurationError("stored LeakCheck limits are invalid") from exc
    return LeakCheckClient(
        api_key,
        requests_per_second=rps,
        concurrency=concurrency,
        max_response_bytes=max_bytes,
        http_client=http_client,
    )


def _parse_page(body: bytes) -> _ParsedPage:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LeakCheckProtocolError("LeakCheck returned malformed JSON") from exc
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise LeakCheckProtocolError("LeakCheck returned an unsuccessful or malformed body")
    raw_results = payload.get("result")
    found = payload.get("found")
    quota = payload.get("quota")
    if (
        not isinstance(raw_results, list)
        or not isinstance(found, int)
        or isinstance(found, bool)
        or found < 0
        or (
            quota is not None
            and (not isinstance(quota, int) or isinstance(quota, bool) or quota < 0)
        )
    ):
        raise LeakCheckProtocolError("LeakCheck response has invalid top-level fields")
    records = tuple(_parse_record(record) for record in raw_results)
    return _ParsedPage(records=records, quota=quota, found=found)


def _parse_record(value: object) -> LeakRecord:
    if not isinstance(value, dict):
        raise LeakCheckProtocolError("LeakCheck result entry is not an object")
    raw = dict(value)
    source_value = value.get("source")
    source = source_value if isinstance(source_value, dict) else {}
    fields_value = value.get("fields")
    fields = (
        tuple(item for item in fields_value if isinstance(item, str))
        if isinstance(fields_value, list)
        else ()
    )
    return LeakRecord(
        email=_optional_string(value.get("email")),
        username=_optional_string(value.get("username")),
        phone=_optional_string(value.get("phone")),
        origin=_optional_origin(value.get("origin")),
        password=_optional_string(value.get("password")),
        fields=fields,
        source=BreachSource(
            name=_optional_string(source.get("name")),
            breach_date=_optional_string(source.get("breach_date")),
            unverified=_optional_bool(source.get("unverified")),
            passwordless=_optional_bool(source.get("passwordless")),
            compilation=_optional_bool(source.get("compilation")),
        ),
        raw=raw,
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_origin(value: object) -> str | None:
    """Accept both legacy scalar origins and LeakCheck's list-valued origin field."""

    if isinstance(value, str):
        return value
    if isinstance(value, list):
        origins = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
        return ", ".join(origins) or None
    return None


def _optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None
