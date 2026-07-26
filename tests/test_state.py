from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from m365_secure_mcp.graph import GraphError, GraphFailure, classify_agent_error
from m365_secure_mcp.security import SecurityError
from m365_secure_mcp.state import IdempotencyStore, WriteRateLimiter


@pytest.mark.asyncio
async def test_idempotency_store_executes_write_only_once(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "state" / "writes.sqlite3", pending_seconds=300)
    calls = 0

    async def operation() -> str:
        nonlocal calls
        calls += 1
        return "created"

    parameters = {"idempotency_key": "key-1", "subject": "sensitive"}
    completed = await store.execute("write", "key-1", parameters, operation)
    assert completed.result == "created"
    assert completed.receipt.status == "completed"
    assert completed.receipt.uncertain_commit is False
    duplicate = await store.execute("write", "key-1", parameters, operation)
    assert "already completed" in duplicate.result
    assert duplicate.receipt.operation_id == completed.receipt.operation_id
    assert duplicate.receipt.duplicate_suppressed is True
    queried = await store.get_receipt(operation_id=completed.receipt.operation_id)
    assert queried == completed.receipt
    assert calls == 1
    assert store.path.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_idempotency_key_is_bound_to_payload(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)

    async def operation() -> str:
        return "created"

    await store.execute("write", "key-1", {"value": "one"}, operation)
    with pytest.raises(SecurityError, match="different payload"):
        await store.execute("write", "key-1", {"value": "two"}, operation)


@pytest.mark.asyncio
async def test_write_ledger_cannot_be_reused_across_tenant_namespaces(
    tmp_path: Path,
) -> None:
    path = tmp_path / "writes.sqlite3"
    first = IdempotencyStore(
        path,
        pending_seconds=300,
        deployment_namespace="tenant-profile-a",
    )

    async def operation() -> str:
        return "created"

    await first.execute("write", "key-1", {"value": "one"}, operation)
    second = IdempotencyStore(
        path,
        pending_seconds=300,
        deployment_namespace="tenant-profile-b",
    )
    with pytest.raises(SecurityError, match="different tenant/profile"):
        await second.get_receipt(tool="write", idempotency_key="key-1")


@pytest.mark.asyncio
async def test_uncertain_write_is_not_automatically_retried(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)

    async def uncertain() -> str:
        raise TimeoutError

    with pytest.raises(TimeoutError):
        await store.execute("write", "key-1", {"value": "one"}, uncertain)
    receipt = await store.get_receipt(tool="write", idempotency_key="key-1")
    assert receipt is not None
    assert receipt.status == "uncertain"
    assert receipt.uncertain_commit is True
    with pytest.raises(SecurityError, match="may still have committed"):
        await store.execute("write", "key-1", {"value": "one"}, uncertain)


@pytest.mark.asyncio
async def test_rejected_write_can_reuse_the_same_key(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)
    calls = 0

    async def operation() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise SecurityError("blocked by local policy")
        return "created"

    operation_id = uuid4()
    with pytest.raises(SecurityError, match="blocked by local policy"):
        await store.execute(
            "write",
            "key-1",
            {"value": "one"},
            operation,
            operation_id=operation_id,
        )
    rejected = await store.get_receipt(operation_id=operation_id)
    assert rejected is not None
    assert rejected.status == "rejected"
    assert rejected.last_error_code == "POLICY_REJECTED"

    completed = await store.execute("write", "key-1", {"value": "one"}, operation)
    assert completed.result == "created"
    assert completed.receipt.operation_id == operation_id
    assert completed.receipt.status == "completed"


@pytest.mark.asyncio
async def test_failure_after_graph_write_attempt_is_always_uncertain(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)

    async def postcondition_failure() -> str:
        raise SecurityError("unexpected postcondition")

    with pytest.raises(SecurityError, match="unexpected postcondition"):
        await store.execute(
            "write",
            "key-1",
            {"value": "one"},
            postcondition_failure,
            write_attempted=lambda: True,
        )
    receipt = await store.get_receipt(tool="write", idempotency_key="key-1")
    assert receipt is not None
    assert receipt.status == "uncertain"
    assert receipt.uncertain_commit is True


@pytest.mark.asyncio
async def test_failure_after_confirmed_write_is_uncertain_even_when_read_returns_404(
    tmp_path: Path,
) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)

    async def verification_failure() -> str:
        raise GraphError(
            "verification resource was not found",
            GraphFailure(404, "verification-read", None),
        )

    with pytest.raises(GraphError):
        await store.execute(
            "write",
            "key-1",
            {"value": "one"},
            verification_failure,
            write_confirmed=lambda: True,
        )
    receipt = await store.get_receipt(tool="write", idempotency_key="key-1")
    assert receipt is not None
    assert receipt.status == "uncertain"
    assert receipt.uncertain_commit is True


@pytest.mark.asyncio
async def test_direct_graph_412_without_prior_success_is_rejected(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)

    async def stale_etag() -> str:
        raise GraphError(
            "resource changed",
            GraphFailure(412, "stale-etag", None),
        )

    with pytest.raises(GraphError):
        await store.execute(
            "write",
            "key-1",
            {"value": "one"},
            stale_etag,
            write_attempted=lambda: True,
        )
    receipt = await store.get_receipt(tool="write", idempotency_key="key-1")
    assert receipt is not None
    assert receipt.status == "rejected"
    assert receipt.uncertain_commit is False


@pytest.mark.asyncio
async def test_write_rate_limiter_is_per_tool() -> None:
    limiter = WriteRateLimiter(per_minute=1)
    await limiter.acquire("tool-a")
    await limiter.acquire("tool-b")
    with pytest.raises(SecurityError, match="rate limit") as caught:
        await limiter.acquire("tool-a")
    details = classify_agent_error(caught.value)
    assert details.code == "LOCAL_RATE_LIMITED"
    assert details.safe_to_retry is True
    assert details.retry_after_seconds is not None
