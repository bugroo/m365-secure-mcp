from __future__ import annotations

from pathlib import Path

import pytest

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
    assert await store.execute("write", "key-1", parameters, operation) == "created"
    duplicate = await store.execute("write", "key-1", parameters, operation)
    assert "already completed" in duplicate
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
async def test_uncertain_write_is_not_automatically_retried(tmp_path: Path) -> None:
    store = IdempotencyStore(tmp_path / "writes.sqlite3", pending_seconds=300)

    async def uncertain() -> str:
        raise TimeoutError

    with pytest.raises(TimeoutError):
        await store.execute("write", "key-1", {"value": "one"}, uncertain)
    with pytest.raises(SecurityError, match="may still be in flight"):
        await store.execute("write", "key-1", {"value": "one"}, uncertain)


@pytest.mark.asyncio
async def test_write_rate_limiter_is_per_tool() -> None:
    limiter = WriteRateLimiter(per_minute=1)
    await limiter.acquire("tool-a")
    await limiter.acquire("tool-b")
    with pytest.raises(SecurityError, match="rate limit"):
        await limiter.acquire("tool-a")
