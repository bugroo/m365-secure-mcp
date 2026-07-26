"""Local write safety state: idempotency and bounded execution rate."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

from .security import SecurityError


class WriteRateLimiter:
    """Process-local fixed-window guard applied independently to each write tool."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def acquire(self, tool: str) -> None:
        now = time.monotonic()
        async with self._lock:
            events = self._events[tool]
            while events and events[0] <= now - 60:
                events.popleft()
            if len(events) >= self.per_minute:
                raise SecurityError(
                    f"local write rate limit reached for '{tool}'; wait before retrying"
                )
            events.append(now)


class IdempotencyStore:
    """Fail-closed SQLite ledger that prevents duplicate Graph writes."""

    def __init__(self, path: Path, *, pending_seconds: int) -> None:
        self.path = path
        self.pending_seconds = pending_seconds
        self._lock = asyncio.Lock()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        os.chmod(self.path, 0o600)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS operations (
                tool TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_unix REAL NOT NULL,
                PRIMARY KEY (tool, idempotency_key)
            )
            """
        )
        return connection

    @staticmethod
    def _payload_hash(parameters: Mapping[str, Any]) -> str:
        canonical = json.dumps(parameters, default=str, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    async def execute(
        self,
        tool: str,
        key: str,
        parameters: Mapping[str, Any],
        operation: Callable[[], Awaitable[str]],
    ) -> str:
        payload_hash = self._payload_hash(parameters)
        async with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT payload_sha256, status, created_unix
                    FROM operations
                    WHERE tool = ? AND idempotency_key = ?
                    """,
                    (tool, key),
                ).fetchone()
                if row is not None:
                    stored_hash, status, created = row
                    if stored_hash != payload_hash:
                        raise SecurityError(
                            "idempotency key was already used with a different payload"
                        )
                    if status == "completed":
                        connection.execute("COMMIT")
                        return (
                            "Write already completed for this idempotency key; "
                            "no duplicate Microsoft Graph call was made."
                        )
                    age = time.time() - float(created)
                    if age < self.pending_seconds:
                        raise SecurityError(
                            "an earlier write with this idempotency key may still be in flight; "
                            "manual verification is required before using a new key"
                        )
                    connection.execute(
                        """
                        UPDATE operations
                        SET status = 'pending', created_unix = ?
                        WHERE tool = ? AND idempotency_key = ?
                        """,
                        (time.time(), tool, key),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO operations
                            (tool, idempotency_key, payload_sha256, status, created_unix)
                        VALUES (?, ?, ?, 'pending', ?)
                        """,
                        (tool, key, payload_hash, time.time()),
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

        try:
            result = await operation()
        except Exception:
            # Keep the pending marker: Graph may have committed before a timeout or disconnect.
            raise

        async with self._lock:
            connection = self._connect()
            try:
                connection.execute(
                    """
                    UPDATE operations
                    SET status = 'completed'
                    WHERE tool = ? AND idempotency_key = ? AND payload_sha256 = ?
                    """,
                    (tool, key, payload_hash),
                )
            finally:
                connection.close()
        return result
