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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from .auth import AuthenticationError
from .graph import GraphError, classify_agent_error
from .protocol import WriteReceipt
from .security import SecurityError, open_private_file


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
                retry_after = max(events[0] + 60 - now, 0.0)
                raise LocalRateLimitError(
                    f"local write rate limit reached for '{tool}'; wait before retrying",
                    retry_after_seconds=retry_after,
                )
            events.append(now)


class LocalRateLimitError(SecurityError):
    """A bounded local write throttle with explicit retry timing."""

    def __init__(self, message: str, *, retry_after_seconds: float) -> None:
        super().__init__(message)
        self.local_rate_limit = True
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class WriteExecution:
    """One write result paired with its durable metadata-only receipt."""

    result: str
    receipt: WriteReceipt


class WriteStateError(SecurityError):
    """A ledger rejection that carries the related operation receipt."""

    def __init__(self, message: str, receipt: WriteReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.write_state_conflict = True


class IdempotencyStore:
    """Fail-closed SQLite ledger that prevents duplicate Graph writes."""

    def __init__(self, path: Path, *, pending_seconds: int) -> None:
        self.path = path
        self.pending_seconds = pending_seconds
        self._lock = asyncio.Lock()

    def _connect(self) -> sqlite3.Connection:
        descriptor = open_private_file(self.path, os.O_RDWR)
        os.close(descriptor)
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
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
                operation_id TEXT,
                updated_unix REAL,
                completed_unix REAL,
                uncertain_commit INTEGER NOT NULL DEFAULT 0,
                last_error_code TEXT,
                PRIMARY KEY (tool, idempotency_key)
            )
            """
        )
        self._migrate(connection)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        """Add receipt columns without discarding ledgers created by older releases."""

        existing = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(operations)").fetchall()
        }
        migrations = {
            "operation_id": "ALTER TABLE operations ADD COLUMN operation_id TEXT",
            "updated_unix": "ALTER TABLE operations ADD COLUMN updated_unix REAL",
            "completed_unix": "ALTER TABLE operations ADD COLUMN completed_unix REAL",
            "uncertain_commit": (
                "ALTER TABLE operations ADD COLUMN uncertain_commit INTEGER NOT NULL DEFAULT 0"
            ),
            "last_error_code": "ALTER TABLE operations ADD COLUMN last_error_code TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing:
                connection.execute(statement)

        rows = connection.execute(
            """
            SELECT tool, idempotency_key, payload_sha256, created_unix
            FROM operations
            WHERE operation_id IS NULL OR updated_unix IS NULL
            """
        ).fetchall()
        for tool, key, payload_hash, created in rows:
            operation_id = str(
                uuid5(
                    NAMESPACE_URL,
                    f"m365-secure-mcp:{tool}:{key}:{payload_hash}",
                )
            )
            connection.execute(
                """
                UPDATE operations
                SET operation_id = COALESCE(operation_id, ?),
                    updated_unix = COALESCE(updated_unix, ?),
                    completed_unix = CASE
                        WHEN status = 'completed' THEN COALESCE(completed_unix, ?)
                        ELSE completed_unix
                    END
                WHERE tool = ? AND idempotency_key = ?
                """,
                (operation_id, created, created, tool, key),
            )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS operations_operation_id
            ON operations(operation_id)
            WHERE operation_id IS NOT NULL
            """
        )

    @staticmethod
    def _payload_hash(parameters: Mapping[str, Any]) -> str:
        canonical = json.dumps(parameters, default=str, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _timestamp(value: float | None) -> str | None:
        if value is None:
            return None
        return datetime.fromtimestamp(float(value), UTC).isoformat()

    @classmethod
    def _receipt(cls, row: sqlite3.Row, *, duplicate: bool = False) -> WriteReceipt:
        created_at = cls._timestamp(row["created_unix"])
        updated_at = cls._timestamp(row["updated_unix"])
        if created_at is None or updated_at is None:
            raise SecurityError("write ledger contains an invalid timestamp")
        return WriteReceipt(
            operation_id=UUID(str(row["operation_id"])),
            tool=str(row["tool"]),
            idempotency_key=str(row["idempotency_key"]),
            status=str(row["status"]),  # type: ignore[arg-type]
            created_at=created_at,
            updated_at=updated_at,
            completed_at=cls._timestamp(row["completed_unix"]),
            duplicate_suppressed=duplicate,
            uncertain_commit=bool(row["uncertain_commit"]),
            last_error_code=(
                str(row["last_error_code"]) if row["last_error_code"] is not None else None
            ),
        )

    @staticmethod
    def _failure_status(exc: Exception, *, write_attempted: bool) -> str:
        if isinstance(exc, GraphError):
            failure = exc.failure
            if failure is not None and 400 <= failure.status_code < 500:
                return "rejected"
        if write_attempted:
            return "uncertain"
        if isinstance(exc, (AuthenticationError, SecurityError, ValueError)):
            return "rejected"
        return "uncertain"

    async def get_receipt(
        self,
        *,
        operation_id: UUID | None = None,
        tool: str | None = None,
        idempotency_key: str | None = None,
    ) -> WriteReceipt | None:
        """Read one receipt by public operation ID or exact tool/key pair."""

        if operation_id is None and (tool is None or idempotency_key is None):
            raise ValueError("operation_id or both tool and idempotency_key are required")
        async with self._lock:
            connection = self._connect()
            try:
                if operation_id is not None:
                    row = connection.execute(
                        "SELECT * FROM operations WHERE operation_id = ?",
                        (str(operation_id),),
                    ).fetchone()
                else:
                    row = connection.execute(
                        """
                        SELECT * FROM operations
                        WHERE tool = ? AND idempotency_key = ?
                        """,
                        (tool, idempotency_key),
                    ).fetchone()
            finally:
                connection.close()
        return self._receipt(row) if row is not None else None

    async def execute(
        self,
        tool: str,
        key: str,
        parameters: Mapping[str, Any],
        operation: Callable[[], Awaitable[str]],
        *,
        operation_id: UUID | None = None,
        write_attempted: Callable[[], bool] | None = None,
    ) -> WriteExecution:
        payload_hash = self._payload_hash(parameters)
        requested_operation_id = operation_id or uuid4()
        active_operation_id = requested_operation_id
        async with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT *
                    FROM operations
                    WHERE tool = ? AND idempotency_key = ?
                    """,
                    (tool, key),
                ).fetchone()
                if row is not None:
                    stored_hash = str(row["payload_sha256"])
                    status = str(row["status"])
                    if stored_hash != payload_hash:
                        raise SecurityError(
                            "idempotency key was already used with a different payload"
                        )
                    if status == "completed":
                        connection.execute("COMMIT")
                        return WriteExecution(
                            result=(
                                "Write already completed for this idempotency key; "
                                "no duplicate Microsoft Graph call was made."
                            ),
                            receipt=self._receipt(row, duplicate=True),
                        )
                    if status in {"pending", "uncertain"}:
                        age = time.time() - float(row["updated_unix"])
                        if status == "pending" and age >= self.pending_seconds:
                            connection.execute(
                                """
                                UPDATE operations
                                SET status = 'uncertain',
                                    updated_unix = ?,
                                    uncertain_commit = 1,
                                    last_error_code = 'PROCESS_INTERRUPTED'
                                WHERE tool = ? AND idempotency_key = ?
                                """,
                                (time.time(), tool, key),
                            )
                            row = connection.execute(
                                """
                                SELECT * FROM operations
                                WHERE tool = ? AND idempotency_key = ?
                                """,
                                (tool, key),
                            ).fetchone()
                            if row is None:
                                raise SecurityError(
                                    "write receipt disappeared during reconciliation"
                                )
                        connection.execute("COMMIT")
                        receipt = self._receipt(row)
                        raise WriteStateError(
                            "an earlier write with this idempotency key may still have committed; "
                            f"inspect operation {receipt.operation_id} before any retry",
                            receipt,
                        )
                    active_operation_id = UUID(str(row["operation_id"]))
                    now = time.time()
                    connection.execute(
                        """
                        UPDATE operations
                        SET status = 'pending',
                            updated_unix = ?,
                            uncertain_commit = 0,
                            last_error_code = NULL
                        WHERE tool = ? AND idempotency_key = ?
                        """,
                        (now, tool, key),
                    )
                else:
                    now = time.time()
                    connection.execute(
                        """
                        INSERT INTO operations
                            (
                                tool,
                                idempotency_key,
                                payload_sha256,
                                status,
                                created_unix,
                                operation_id,
                                updated_unix
                            )
                        VALUES (?, ?, ?, 'pending', ?, ?, ?)
                        """,
                        (
                            tool,
                            key,
                            payload_hash,
                            now,
                            str(requested_operation_id),
                            now,
                        ),
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
        except Exception as exc:
            status = self._failure_status(
                exc,
                write_attempted=write_attempted() if write_attempted is not None else False,
            )
            details = classify_agent_error(exc)
            async with self._lock:
                connection = self._connect()
                try:
                    connection.execute(
                        """
                        UPDATE operations
                        SET status = ?,
                            updated_unix = ?,
                            uncertain_commit = ?,
                            last_error_code = ?
                        WHERE tool = ? AND idempotency_key = ? AND payload_sha256 = ?
                        """,
                        (
                            status,
                            time.time(),
                            int(status == "uncertain"),
                            details.code,
                            tool,
                            key,
                            payload_hash,
                        ),
                    )
                finally:
                    connection.close()
            raise

        async with self._lock:
            connection = self._connect()
            try:
                connection.execute(
                    """
                    UPDATE operations
                    SET status = 'completed',
                        updated_unix = ?,
                        completed_unix = ?,
                        uncertain_commit = 0,
                        last_error_code = NULL
                    WHERE tool = ? AND idempotency_key = ? AND payload_sha256 = ?
                    """,
                    (time.time(), time.time(), tool, key, payload_hash),
                )
                row = connection.execute(
                    """
                    SELECT * FROM operations
                    WHERE tool = ? AND idempotency_key = ?
                    """,
                    (tool, key),
                ).fetchone()
            finally:
                connection.close()
        if row is None:
            raise SecurityError("write receipt disappeared after completion")
        receipt = self._receipt(row)
        if receipt.operation_id != active_operation_id:
            raise SecurityError("write receipt operation identity changed unexpectedly")
        return WriteExecution(result=result, receipt=receipt)
