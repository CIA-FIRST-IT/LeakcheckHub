"""Batch queue safety properties that do not require live services."""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from sqlalchemy.dialects import postgresql

from app.batches import claim_statement
from app.leakcheck import LeakCheckClient, QueryType
from app.models import ScanBatch, ScanQueue


def test_claim_is_atomic_and_skips_rows_locked_by_other_workers() -> None:
    sql = str(
        claim_statement("worker-a").compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    ).upper()
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "UPDATE SCAN_QUEUE" in sql
    assert "ATTEMPTS=(SCAN_QUEUE.ATTEMPTS + 1)" in sql


def test_batch_schema_is_durable_and_deduplicates_subjects() -> None:
    constraints = {constraint.name for constraint in ScanQueue.__table__.constraints}
    assert "uq_scan_queue_batch_subject" in constraints
    assert ScanBatch.__table__.c.total_count.server_default is not None
    assert ScanQueue.__table__.c.locked_at.nullable is True


@pytest.mark.anyio
async def test_shared_client_self_paces_concurrent_batch_load() -> None:
    sent_at: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        sent_at.append(time.monotonic())
        return httpx.Response(
            200,
            content=json.dumps({"success": True, "quota": 100, "found": 0, "result": []}).encode(),
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = LeakCheckClient(
        "configured-key", requests_per_second=10, concurrency=10, http_client=http_client
    )
    try:
        await asyncio.gather(
            *(client.query(QueryType.EMAIL, f"user-{index}@example.com") for index in range(4))
        )
    finally:
        await http_client.aclose()
    assert len(sent_at) == 4
    assert sent_at[-1] - sent_at[0] >= 0.27
