"""Durable provider-neutral lifecycle for approved effectful operations."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .contract_manifest import canonical_json
from .operator_authority import OperatorPlan, PreconditionBinding
from .security import SecurityError, open_private_file


class StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OperatorLifecycleStatus(StrEnum):
    PLANNED = "PLANNED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    EXECUTED_ACCEPTED = "EXECUTED_ACCEPTED"
    OBSERVING = "OBSERVING"
    EXECUTED_VERIFIED = "EXECUTED_VERIFIED"
    EXECUTED_UNCERTAIN = "EXECUTED_UNCERTAIN"
    TIMED_OUT = "TIMED_OUT"
    FAILED_CONFIRMED = "FAILED_CONFIRMED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    COMPENSATION_REQUIRED = "COMPENSATION_REQUIRED"
    COMPLETED = "COMPLETED"


class ProviderExecutionKind(StrEnum):
    VERIFIED = "verified"
    ACCEPTED = "accepted"
    FAILED_CONFIRMED = "failed_confirmed"
    UNCERTAIN = "uncertain"


class ProviderObservationKind(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED_CONFIRMED = "failed_confirmed"
    UNCERTAIN = "uncertain"


class ProviderExecutionResult(StrictFrozenModel):
    kind: ProviderExecutionKind
    evidence_reference: str = Field(pattern=r"^evidence:[0-9a-f]{32,64}$")
    observation_handle: str | None = Field(
        default=None,
        pattern=r"^observation:[0-9a-f]{32,64}$",
    )

    @model_validator(mode="after")
    def accepted_requires_handle(self) -> ProviderExecutionResult:
        if (
            self.kind is ProviderExecutionKind.ACCEPTED
            and self.observation_handle is None
        ):
            raise ValueError("accepted provider result requires an observation handle")
        if (
            self.kind is not ProviderExecutionKind.ACCEPTED
            and self.observation_handle is not None
        ):
            raise ValueError("only accepted provider results may expose a handle")
        return self


class ProviderObservationResult(StrictFrozenModel):
    kind: ProviderObservationKind
    evidence_reference: str = Field(pattern=r"^evidence:[0-9a-f]{32,64}$")


class OperationProvider(Protocol):
    """Closed code adapter implemented per compiled contract, never from tool input."""

    async def preflight(
        self,
        plan: OperatorPlan,
    ) -> tuple[PreconditionBinding, ...]: ...

    async def execute(self, plan: OperatorPlan) -> ProviderExecutionResult: ...

    async def observe(
        self,
        observation_handle: str,
    ) -> ProviderObservationResult: ...

    @property
    def supports_cancellation(self) -> bool: ...

    async def cancel(
        self,
        observation_handle: str,
    ) -> ProviderObservationResult: ...


class ProviderTransportError(RuntimeError):
    """Transport failure with an explicit provider-commit ambiguity boundary."""

    def __init__(self, message: str, *, commit_possible: bool) -> None:
        super().__init__(message)
        self.commit_possible = commit_possible


class DurableOperationRecord(StrictFrozenModel):
    """Private metadata-only durable state; target and parameters are absent."""

    schema_version: str = "1.0"
    operation_id: UUID
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect_model_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    deployment_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    status: OperatorLifecycleStatus
    observation_handle: str | None = Field(
        default=None,
        pattern=r"^observation:[0-9a-f]{32,64}$",
    )
    evidence_reference: str | None = Field(
        default=None,
        pattern=r"^evidence:[0-9a-f]{32,64}$",
    )
    poll_count: int = Field(default=0, ge=0, le=100)
    max_polls: int = Field(ge=1, le=100)
    created_at: datetime
    updated_at: datetime
    observation_deadline: datetime
    terminal_reason: str | None = Field(
        default=None,
        pattern=r"^[A-Z][A-Z0-9_]{2,63}$",
    )

    @model_validator(mode="after")
    def timestamps_and_handle_are_consistent(self) -> DurableOperationRecord:
        timestamps = (self.created_at, self.updated_at, self.observation_deadline)
        if any(item.tzinfo is None or item.utcoffset() is None for item in timestamps):
            raise ValueError("durable operation timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise ValueError("durable operation update precedes creation")
        if self.status in {
            OperatorLifecycleStatus.EXECUTED_ACCEPTED,
            OperatorLifecycleStatus.OBSERVING,
        } and self.observation_handle is None:
            raise ValueError("accepted or observing state requires an opaque handle")
        return self


class PublicOperationProgress(StrictFrozenModel):
    """Bounded MCP-safe projection with no tenant, target, parameter, or signer."""

    status: OperatorLifecycleStatus
    operation_reference: str = Field(pattern=r"^operation:[0-9a-f-]{36}$")
    evidence_reference: str | None
    observation_reference: str | None
    safe_to_retry: bool
    operator_action: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")


_ALLOWED_TRANSITIONS: dict[
    OperatorLifecycleStatus,
    frozenset[OperatorLifecycleStatus],
] = {
    OperatorLifecycleStatus.PLANNED: frozenset(
        {OperatorLifecycleStatus.AWAITING_APPROVAL}
    ),
    OperatorLifecycleStatus.AWAITING_APPROVAL: frozenset(
        {OperatorLifecycleStatus.AUTHORIZED}
    ),
    OperatorLifecycleStatus.AUTHORIZED: frozenset(
        {
            OperatorLifecycleStatus.EXECUTING,
            OperatorLifecycleStatus.FAILED_CONFIRMED,
        }
    ),
    OperatorLifecycleStatus.EXECUTING: frozenset(
        {
            OperatorLifecycleStatus.EXECUTED_ACCEPTED,
            OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
            OperatorLifecycleStatus.EXECUTED_VERIFIED,
            OperatorLifecycleStatus.FAILED_CONFIRMED,
        }
    ),
    OperatorLifecycleStatus.EXECUTED_ACCEPTED: frozenset(
        {OperatorLifecycleStatus.OBSERVING}
    ),
    OperatorLifecycleStatus.OBSERVING: frozenset(
        {
            OperatorLifecycleStatus.OBSERVING,
            OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
            OperatorLifecycleStatus.EXECUTED_VERIFIED,
            OperatorLifecycleStatus.FAILED_CONFIRMED,
            OperatorLifecycleStatus.TIMED_OUT,
        }
    ),
    OperatorLifecycleStatus.EXECUTED_VERIFIED: frozenset(
        {OperatorLifecycleStatus.COMPLETED}
    ),
    OperatorLifecycleStatus.EXECUTED_UNCERTAIN: frozenset(
        {OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED}
    ),
    OperatorLifecycleStatus.TIMED_OUT: frozenset(
        {OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED}
    ),
    OperatorLifecycleStatus.FAILED_CONFIRMED: frozenset(
        {OperatorLifecycleStatus.COMPLETED}
    ),
    OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED: frozenset(
        {OperatorLifecycleStatus.COMPENSATION_REQUIRED}
    ),
    OperatorLifecycleStatus.COMPENSATION_REQUIRED: frozenset(),
    OperatorLifecycleStatus.COMPLETED: frozenset(),
}


class DurableOperationStore:
    """Tenant/profile-bound SQLite state with exact transition validation."""

    def __init__(self, path: Path, deployment_namespace: str) -> None:
        self.path = path
        self.deployment_namespace = deployment_namespace

    def _connect(self) -> sqlite3.Connection:
        descriptor = open_private_file(self.path, os.O_RDWR)
        os.close(descriptor)
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS lifecycle_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                deployment_namespace TEXT NOT NULL
            )
            """
        )
        row = connection.execute(
            "SELECT deployment_namespace FROM lifecycle_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO lifecycle_metadata (singleton, deployment_namespace)
                VALUES (1, ?)
                """,
                (self.deployment_namespace,),
            )
        elif str(row[0]) != self.deployment_namespace:
            connection.close()
            raise SecurityError("operation lifecycle belongs to another deployment")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS operation_lifecycle (
                operation_id TEXT PRIMARY KEY,
                plan_digest TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                record_json BLOB NOT NULL
            )
            """
        )
        return connection

    @staticmethod
    def _decode(payload: bytes) -> DurableOperationRecord:
        try:
            return DurableOperationRecord.model_validate_json(payload)
        except ValueError as exc:
            raise SecurityError("durable operation state is malformed") from exc

    def get(self, operation_id: UUID) -> DurableOperationRecord | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT record_json FROM operation_lifecycle WHERE operation_id = ?",
                (str(operation_id),),
            ).fetchone()
        finally:
            connection.close()
        return self._decode(bytes(row[0])) if row is not None else None

    def ensure(
        self,
        plan: OperatorPlan,
        *,
        operation_id: UUID,
        as_of: datetime,
        observation_deadline: datetime,
        max_polls: int,
    ) -> DurableOperationRecord:
        existing = self.get(operation_id)
        if existing is not None:
            if (
                existing.plan_digest != plan.digest
                or existing.contract_digest != plan.contract_digest
                or existing.contract_manifest_digest
                != plan.contract_manifest_digest
                or existing.effect_model_digest != plan.effect_model_digest
                or existing.policy_digest != plan.policy_digest
                or existing.playbook_digest != plan.playbook_digest
            ):
                raise SecurityError("durable operation cannot resume with changed digests")
            return existing
        record = DurableOperationRecord(
            operation_id=operation_id,
            plan_digest=plan.digest,
            contract_digest=plan.contract_digest,
            contract_manifest_digest=plan.contract_manifest_digest,
            effect_model_digest=plan.effect_model_digest,
            policy_digest=plan.policy_digest,
            playbook_digest=plan.playbook_digest,
            deployment_namespace=self.deployment_namespace,
            status=OperatorLifecycleStatus.PLANNED,
            max_polls=max_polls,
            created_at=as_of,
            updated_at=as_of,
            observation_deadline=observation_deadline,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO operation_lifecycle (
                    operation_id, plan_digest, status, record_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    str(operation_id),
                    plan.digest,
                    record.status.value,
                    canonical_json(record),
                ),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise SecurityError("operation or plan already has durable state") from exc
        finally:
            connection.close()
        return record

    def transition(
        self,
        current: DurableOperationRecord,
        status: OperatorLifecycleStatus,
        *,
        as_of: datetime,
        observation_handle: str | None = None,
        evidence_reference: str | None = None,
        increment_poll: bool = False,
        terminal_reason: str | None = None,
    ) -> DurableOperationRecord:
        if status not in _ALLOWED_TRANSITIONS[current.status]:
            raise SecurityError(
                f"invalid operator lifecycle transition: {current.status} -> {status}"
            )
        updated = current.model_copy(
            update={
                "status": status,
                "updated_at": as_of,
                "observation_handle": (
                    observation_handle
                    if observation_handle is not None
                    else current.observation_handle
                ),
                "evidence_reference": (
                    evidence_reference
                    if evidence_reference is not None
                    else current.evidence_reference
                ),
                "poll_count": current.poll_count + int(increment_poll),
                "terminal_reason": terminal_reason,
            }
        )
        updated = DurableOperationRecord.model_validate(
            updated.model_dump(mode="python")
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """
                UPDATE operation_lifecycle
                SET status = ?, record_json = ?
                WHERE operation_id = ? AND status = ? AND plan_digest = ?
                """,
                (
                    updated.status.value,
                    canonical_json(updated),
                    str(updated.operation_id),
                    current.status.value,
                    current.plan_digest,
                ),
            )
            if result.rowcount != 1:
                raise SecurityError("durable operation state changed concurrently")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return updated


class DurableOperatorLifecycle:
    """Execute and observe one exact plan without duplicate provider effects."""

    def __init__(self, store: DurableOperationStore) -> None:
        self.store = store

    @staticmethod
    def public(record: DurableOperationRecord) -> PublicOperationProgress:
        retryable_terminal_reasons = {
            "PROVIDER_FAILED_CONFIRMED",
            "TRANSPORT_FAILURE_BEFORE_COMMIT",
        }
        safe_to_retry = (
            record.status is OperatorLifecycleStatus.FAILED_CONFIRMED
            or (
                record.status is OperatorLifecycleStatus.COMPLETED
                and record.terminal_reason in retryable_terminal_reasons
            )
        )
        action_by_status = {
            OperatorLifecycleStatus.PLANNED: "operator.submit_for_approval",
            OperatorLifecycleStatus.AWAITING_APPROVAL: "approver.review_exact_plan",
            OperatorLifecycleStatus.AUTHORIZED: "runtime.resume_authorized_plan",
            OperatorLifecycleStatus.EXECUTING: "operator.inspect_possible_commit",
            OperatorLifecycleStatus.EXECUTED_ACCEPTED: "runtime.observe_bounded",
            OperatorLifecycleStatus.OBSERVING: "runtime.observe_bounded",
            OperatorLifecycleStatus.EXECUTED_VERIFIED: "runtime.finalize_receipt",
            OperatorLifecycleStatus.EXECUTED_UNCERTAIN: "operator.manual_verification",
            OperatorLifecycleStatus.TIMED_OUT: "operator.manual_verification",
            OperatorLifecycleStatus.FAILED_CONFIRMED: "operator.create_new_plan_if_needed",
            OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED: "operator.review_private_evidence",
            OperatorLifecycleStatus.COMPENSATION_REQUIRED: (
                "operator.plan_separate_compensation"
            ),
            OperatorLifecycleStatus.COMPLETED: (
                "operator.create_new_plan_if_needed"
                if safe_to_retry
                else "operator.retain_receipt"
            ),
        }
        return PublicOperationProgress(
            status=record.status,
            operation_reference=f"operation:{record.operation_id}",
            evidence_reference=record.evidence_reference,
            observation_reference=record.observation_handle,
            safe_to_retry=safe_to_retry,
            operator_action=action_by_status[record.status],
        )

    async def execute(
        self,
        *,
        plan: OperatorPlan,
        operation_id: UUID,
        provider: OperationProvider,
        as_of: datetime,
        authorized: bool,
        async_allowed: bool,
    ) -> DurableOperationRecord:
        record = self.store.ensure(
            plan,
            operation_id=operation_id,
            as_of=as_of,
            observation_deadline=min(
                plan.expires_at,
                as_of + timedelta(seconds=plan.observation_timeout_seconds),
            ),
            max_polls=plan.maximum_observation_polls,
        )
        if record.status is OperatorLifecycleStatus.COMPLETED:
            return record
        if record.status is OperatorLifecycleStatus.EXECUTING:
            uncertain = self.store.transition(
                record,
                OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
                as_of=as_of,
                terminal_reason="PROCESS_INTERRUPTED_AFTER_EXECUTION_STARTED",
            )
            return self.store.transition(
                uncertain,
                OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
                as_of=as_of,
                terminal_reason="POSSIBLE_PROVIDER_COMMIT",
            )
        if record.status is OperatorLifecycleStatus.PLANNED:
            record = self.store.transition(
                record,
                OperatorLifecycleStatus.AWAITING_APPROVAL,
                as_of=as_of,
            )
        if record.status is OperatorLifecycleStatus.AWAITING_APPROVAL:
            if not authorized:
                return record
            record = self.store.transition(
                record,
                OperatorLifecycleStatus.AUTHORIZED,
                as_of=as_of,
            )
        if record.status is not OperatorLifecycleStatus.AUTHORIZED:
            return record
        if not plan.not_before <= as_of < plan.expires_at:
            failed = self.store.transition(
                record,
                OperatorLifecycleStatus.FAILED_CONFIRMED,
                as_of=as_of,
                terminal_reason="PLAN_WINDOW_EXPIRED",
            )
            return self.store.transition(
                failed,
                OperatorLifecycleStatus.COMPLETED,
                as_of=as_of,
                terminal_reason="PLAN_WINDOW_EXPIRED",
            )
        observed_preconditions = await provider.preflight(plan)
        if observed_preconditions != plan.preconditions:
            failed = self.store.transition(
                record,
                OperatorLifecycleStatus.FAILED_CONFIRMED,
                as_of=as_of,
                terminal_reason="TOCTOU_PRECONDITION_CHANGED",
            )
            return self.store.transition(
                failed,
                OperatorLifecycleStatus.COMPLETED,
                as_of=as_of,
                terminal_reason="TOCTOU_PRECONDITION_CHANGED",
            )
        record = self.store.transition(
            record,
            OperatorLifecycleStatus.EXECUTING,
            as_of=as_of,
        )
        try:
            result = await provider.execute(plan)
        except ProviderTransportError as exc:
            status = (
                OperatorLifecycleStatus.EXECUTED_UNCERTAIN
                if exc.commit_possible
                else OperatorLifecycleStatus.FAILED_CONFIRMED
            )
            reason = (
                "TRANSPORT_FAILURE_AFTER_POSSIBLE_COMMIT"
                if exc.commit_possible
                else "TRANSPORT_FAILURE_BEFORE_COMMIT"
            )
            record = self.store.transition(
                record,
                status,
                as_of=as_of,
                terminal_reason=reason,
            )
        except Exception:
            record = self.store.transition(
                record,
                OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
                as_of=as_of,
                terminal_reason="UNCLASSIFIED_PROVIDER_FAILURE",
            )
        else:
            if result.kind is ProviderExecutionKind.ACCEPTED and not async_allowed:
                record = self.store.transition(
                    record,
                    OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
                    as_of=as_of,
                    evidence_reference=result.evidence_reference,
                    terminal_reason="UNEXPECTED_ASYNC_PROVIDER_ACCEPTANCE",
                )
                return self.store.transition(
                    record,
                    OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
                    as_of=as_of,
                    terminal_reason="UNEXPECTED_ASYNC_PROVIDER_ACCEPTANCE",
                )
            status_by_kind = {
                ProviderExecutionKind.VERIFIED: (
                    OperatorLifecycleStatus.EXECUTED_VERIFIED
                ),
                ProviderExecutionKind.ACCEPTED: (
                    OperatorLifecycleStatus.EXECUTED_ACCEPTED
                ),
                ProviderExecutionKind.FAILED_CONFIRMED: (
                    OperatorLifecycleStatus.FAILED_CONFIRMED
                ),
                ProviderExecutionKind.UNCERTAIN: (
                    OperatorLifecycleStatus.EXECUTED_UNCERTAIN
                ),
            }
            record = self.store.transition(
                record,
                status_by_kind[result.kind],
                as_of=as_of,
                observation_handle=result.observation_handle,
                evidence_reference=result.evidence_reference,
                terminal_reason=(
                    None
                    if result.kind
                    in {ProviderExecutionKind.VERIFIED, ProviderExecutionKind.ACCEPTED}
                    else f"PROVIDER_{result.kind.value.upper()}"
                ),
            )
        if record.status in {
            OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
            OperatorLifecycleStatus.TIMED_OUT,
        }:
            return self.store.transition(
                record,
                OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
                as_of=as_of,
                terminal_reason=record.terminal_reason,
            )
        if record.status in {
            OperatorLifecycleStatus.EXECUTED_VERIFIED,
            OperatorLifecycleStatus.FAILED_CONFIRMED,
        }:
            return self.store.transition(
                record,
                OperatorLifecycleStatus.COMPLETED,
                as_of=as_of,
                terminal_reason=record.terminal_reason,
            )
        return record

    async def observe(
        self,
        *,
        operation_id: UUID,
        provider: OperationProvider,
        as_of: datetime,
    ) -> DurableOperationRecord:
        record = self.store.get(operation_id)
        if record is None:
            raise SecurityError("unknown durable operation")
        if record.status is OperatorLifecycleStatus.EXECUTED_ACCEPTED:
            record = self.store.transition(
                record,
                OperatorLifecycleStatus.OBSERVING,
                as_of=as_of,
            )
        if record.status is not OperatorLifecycleStatus.OBSERVING:
            return record
        if (
            as_of >= record.observation_deadline
            or record.poll_count >= record.max_polls
        ):
            timed_out = self.store.transition(
                record,
                OperatorLifecycleStatus.TIMED_OUT,
                as_of=as_of,
                terminal_reason="OBSERVATION_LIMIT_REACHED",
            )
            return self.store.transition(
                timed_out,
                OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
                as_of=as_of,
                terminal_reason="OBSERVATION_LIMIT_REACHED",
            )
        if record.observation_handle is None:
            raise SecurityError("accepted operation lost its observation handle")
        try:
            result = await provider.observe(record.observation_handle)
        except Exception:
            uncertain = self.store.transition(
                record,
                OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
                as_of=as_of,
                increment_poll=True,
                terminal_reason="OBSERVATION_TRANSPORT_FAILURE",
            )
            return self.store.transition(
                uncertain,
                OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
                as_of=as_of,
                terminal_reason="OBSERVATION_TRANSPORT_FAILURE",
            )
        if result.kind is ProviderObservationKind.PENDING:
            return self.store.transition(
                record,
                OperatorLifecycleStatus.OBSERVING,
                as_of=as_of,
                evidence_reference=result.evidence_reference,
                increment_poll=True,
            )
        status_by_kind = {
            ProviderObservationKind.VERIFIED: OperatorLifecycleStatus.EXECUTED_VERIFIED,
            ProviderObservationKind.FAILED_CONFIRMED: (
                OperatorLifecycleStatus.FAILED_CONFIRMED
            ),
            ProviderObservationKind.UNCERTAIN: (
                OperatorLifecycleStatus.EXECUTED_UNCERTAIN
            ),
        }
        record = self.store.transition(
            record,
            status_by_kind[result.kind],
            as_of=as_of,
            evidence_reference=result.evidence_reference,
            increment_poll=True,
            terminal_reason=(
                None
                if result.kind is ProviderObservationKind.VERIFIED
                else f"PROVIDER_{result.kind.value.upper()}"
            ),
        )
        if record.status is OperatorLifecycleStatus.EXECUTED_UNCERTAIN:
            return self.store.transition(
                record,
                OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
                as_of=as_of,
                terminal_reason=record.terminal_reason,
            )
        return self.store.transition(
            record,
            OperatorLifecycleStatus.COMPLETED,
            as_of=as_of,
            terminal_reason=record.terminal_reason,
        )

    async def cancel(
        self,
        *,
        operation_id: UUID,
        provider: OperationProvider,
        as_of: datetime,
    ) -> DurableOperationRecord:
        record = self.store.get(operation_id)
        if record is None:
            raise SecurityError("unknown durable operation")
        if record.status not in {
            OperatorLifecycleStatus.EXECUTED_ACCEPTED,
            OperatorLifecycleStatus.OBSERVING,
        }:
            raise SecurityError("operation is not in a cancellable provider state")
        if not provider.supports_cancellation or record.observation_handle is None:
            raise SecurityError("provider does not support safe cancellation")
        result = await provider.cancel(record.observation_handle)
        if result.kind is ProviderObservationKind.FAILED_CONFIRMED:
            if record.status is OperatorLifecycleStatus.EXECUTED_ACCEPTED:
                record = self.store.transition(
                    record,
                    OperatorLifecycleStatus.OBSERVING,
                    as_of=as_of,
                )
            failed = self.store.transition(
                record,
                OperatorLifecycleStatus.FAILED_CONFIRMED,
                as_of=as_of,
                evidence_reference=result.evidence_reference,
                terminal_reason="PROVIDER_CANCELLATION_CONFIRMED",
            )
            return self.store.transition(
                failed,
                OperatorLifecycleStatus.COMPLETED,
                as_of=as_of,
                terminal_reason="PROVIDER_CANCELLATION_CONFIRMED",
            )
        raise SecurityError("provider cancellation was not confirmed safe")
