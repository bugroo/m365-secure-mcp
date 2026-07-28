"""Durable closed-registry runner for signed effectful playbook fixtures."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contract_manifest import canonical_json, sha256_digest
from .playbook_manifest import (
    EffectfulExecutorId,
    EffectfulPlaybookNode,
    EffectfulPlaybookSpec,
    VerifiedEffectfulPlaybookManifest,
)
from .security import SecurityError, open_private_file


class StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PlaybookRunStatus(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AWAITING_OBSERVATION = "AWAITING_OBSERVATION"
    PAUSED_UNCERTAIN = "PAUSED_UNCERTAIN"
    MANUAL_HANDOFF = "MANUAL_HANDOFF"
    COMPENSATION_REQUIRED = "COMPENSATION_REQUIRED"
    COMPLETED_VERIFIED = "COMPLETED_VERIFIED"


class PlaybookNodeStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    UNCERTAIN = "UNCERTAIN"
    MANUAL_HANDOFF = "MANUAL_HANDOFF"
    COMPENSATION_REQUIRED = "COMPENSATION_REQUIRED"


class PlaybookNodeOutcome(StrEnum):
    COMPLETED = "completed"
    PAUSE_APPROVAL = "pause_approval"
    PAUSE_OBSERVATION = "pause_observation"
    UNCERTAIN = "uncertain"
    MANUAL_HANDOFF = "manual_handoff"
    COMPENSATION_PROPOSAL = "compensation_proposal"


class EffectfulRunContext(StrictFrozenModel):
    """Exact trusted inputs required to resume one effectful DAG."""

    schema_version: str = "1.0"
    instance_id: UUID
    playbook_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    playbook_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect_model_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    deployment_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")

    @property
    def digest(self) -> str:
        return sha256_digest(self)


class EffectfulPlaybookExecutor(Protocol):
    """Trusted code implementation selected by a closed manifest enum."""

    async def execute(
        self,
        node: EffectfulPlaybookNode,
        context: EffectfulRunContext,
        *,
        resumed: bool,
    ) -> PlaybookNodeOutcome: ...


class EffectfulExecutorRegistry:
    """Code-level registry; manifests cannot add or name arbitrary executors."""

    def __init__(
        self,
        executors: Mapping[EffectfulExecutorId, EffectfulPlaybookExecutor],
    ) -> None:
        self._executors = dict(executors)
        if not self._executors:
            raise ValueError("effectful executor registry cannot be empty")
        if any(not isinstance(key, EffectfulExecutorId) for key in self._executors):
            raise ValueError("effectful executor registry contains an unknown ID")

    def executor(self, executor_id: EffectfulExecutorId) -> EffectfulPlaybookExecutor:
        try:
            return self._executors[executor_id]
        except KeyError as exc:
            raise SecurityError("effectful playbook executor is unavailable") from exc


class DurablePlaybookRun(StrictFrozenModel):
    """Metadata-only checkpoint state; no targets, parameters, or approvals."""

    schema_version: str = "1.0"
    instance_id: UUID
    context_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    playbook_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    playbook_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect_model_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    deployment_namespace: str = Field(pattern=r"^[0-9a-f]{16}$")
    status: PlaybookRunStatus
    node_states: dict[str, PlaybookNodeStatus]
    created_at: datetime
    updated_at: datetime
    pause_reason: str | None = Field(
        default=None,
        pattern=r"^[A-Z][A-Z0-9_]{2,63}$",
    )

    @field_validator("node_states")
    @classmethod
    def node_states_are_sorted(
        cls,
        value: dict[str, PlaybookNodeStatus],
    ) -> dict[str, PlaybookNodeStatus]:
        if list(value) != sorted(value):
            raise ValueError("playbook node states must use deterministic ordering")
        return value

    @model_validator(mode="after")
    def timestamps_are_aware(self) -> DurablePlaybookRun:
        if (
            self.created_at.tzinfo is None
            or self.updated_at.tzinfo is None
            or self.updated_at < self.created_at
        ):
            raise ValueError("playbook checkpoint timestamps are invalid")
        return self


class DurablePlaybookStore:
    """Owner-only checkpoint store fenced to one tenant/profile deployment."""

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
            CREATE TABLE IF NOT EXISTS playbook_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                deployment_namespace TEXT NOT NULL
            )
            """
        )
        row = connection.execute(
            "SELECT deployment_namespace FROM playbook_metadata WHERE singleton = 1"
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO playbook_metadata (singleton, deployment_namespace)
                VALUES (1, ?)
                """,
                (self.deployment_namespace,),
            )
        elif str(row[0]) != self.deployment_namespace:
            connection.close()
            raise SecurityError("playbook checkpoint belongs to another deployment")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS effectful_playbooks (
                instance_id TEXT PRIMARY KEY,
                context_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                record_json BLOB NOT NULL
            )
            """
        )
        return connection

    @staticmethod
    def _decode(payload: bytes) -> DurablePlaybookRun:
        try:
            return DurablePlaybookRun.model_validate_json(payload)
        except ValueError as exc:
            raise SecurityError("durable playbook state is malformed") from exc

    def get(self, instance_id: UUID) -> DurablePlaybookRun | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT record_json FROM effectful_playbooks WHERE instance_id = ?",
                (str(instance_id),),
            ).fetchone()
        finally:
            connection.close()
        return self._decode(bytes(row[0])) if row is not None else None

    def ensure(
        self,
        playbook: EffectfulPlaybookSpec,
        context: EffectfulRunContext,
        *,
        as_of: datetime,
    ) -> DurablePlaybookRun:
        existing = self.get(context.instance_id)
        if existing is not None:
            if existing.context_digest != context.digest:
                raise SecurityError("playbook cannot resume with changed trusted digests")
            return existing
        record = DurablePlaybookRun(
            instance_id=context.instance_id,
            context_digest=context.digest,
            playbook_id=context.playbook_id,
            playbook_manifest_digest=context.playbook_manifest_digest,
            playbook_digest=context.playbook_digest,
            contract_manifest_digest=context.contract_manifest_digest,
            effect_model_digest=context.effect_model_digest,
            policy_digest=context.policy_digest,
            plan_digest=context.plan_digest,
            contract_digest=context.contract_digest,
            deployment_namespace=context.deployment_namespace,
            status=PlaybookRunStatus.PLANNED,
            node_states={
                node.id: PlaybookNodeStatus.PENDING
                for node in sorted(playbook.nodes, key=lambda item: item.id)
            },
            created_at=as_of,
            updated_at=as_of,
        )
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO effectful_playbooks (
                    instance_id, context_digest, status, record_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    str(record.instance_id),
                    record.context_digest,
                    record.status.value,
                    canonical_json(record),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise SecurityError("playbook instance already exists") from exc
        finally:
            connection.close()
        return record

    def replace(
        self,
        current: DurablePlaybookRun,
        updated: DurablePlaybookRun,
    ) -> DurablePlaybookRun:
        if current.instance_id != updated.instance_id:
            raise SecurityError("playbook checkpoint identity changed")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """
                UPDATE effectful_playbooks
                SET status = ?, record_json = ?
                WHERE instance_id = ? AND status = ? AND context_digest = ?
                """,
                (
                    updated.status.value,
                    canonical_json(updated),
                    str(current.instance_id),
                    current.status.value,
                    current.context_digest,
                ),
            )
            if result.rowcount != 1:
                raise SecurityError("playbook checkpoint changed concurrently")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return updated


class EffectfulPlaybookRunner:
    """Advance at most one deterministic DAG node per call."""

    def __init__(
        self,
        *,
        store: DurablePlaybookStore,
        executors: EffectfulExecutorRegistry,
    ) -> None:
        self.store = store
        self.executors = executors

    @staticmethod
    def _validated_playbook(
        verified: VerifiedEffectfulPlaybookManifest,
        context: EffectfulRunContext,
    ) -> EffectfulPlaybookSpec:
        if verified.manifest_digest != context.playbook_manifest_digest:
            raise SecurityError("playbook manifest digest changed")
        try:
            playbook = verified.manifest.playbook(context.playbook_id)
        except KeyError as exc:
            raise SecurityError("playbook is absent from the signed manifest") from exc
        if (
            sha256_digest(playbook) != context.playbook_digest
            or playbook.contract_manifest_digest
            != context.contract_manifest_digest
            or playbook.effect_model_digest != context.effect_model_digest
        ):
            raise SecurityError("playbook trusted digests do not match")
        return playbook

    async def step(
        self,
        *,
        verified_manifest: VerifiedEffectfulPlaybookManifest,
        context: EffectfulRunContext,
        as_of: datetime,
    ) -> DurablePlaybookRun:
        playbook = self._validated_playbook(verified_manifest, context)
        record = self.store.ensure(playbook, context, as_of=as_of)
        if record.status in {
            PlaybookRunStatus.PAUSED_UNCERTAIN,
            PlaybookRunStatus.MANUAL_HANDOFF,
            PlaybookRunStatus.COMPENSATION_REQUIRED,
            PlaybookRunStatus.COMPLETED_VERIFIED,
        }:
            return record
        running = [
            node_id
            for node_id, status in record.node_states.items()
            if status is PlaybookNodeStatus.RUNNING
        ]
        if running:
            node_states = dict(record.node_states)
            for node_id in running:
                node_states[node_id] = PlaybookNodeStatus.UNCERTAIN
            updated = DurablePlaybookRun.model_validate(
                record.model_copy(
                    update={
                        "status": PlaybookRunStatus.PAUSED_UNCERTAIN,
                        "node_states": node_states,
                        "updated_at": as_of,
                        "pause_reason": "PROCESS_INTERRUPTED_DURING_NODE",
                    }
                ).model_dump(mode="python")
            )
            return self.store.replace(record, updated)

        nodes_by_id = {node.id: node for node in playbook.nodes}
        paused = sorted(
            node_id
            for node_id, status in record.node_states.items()
            if status is PlaybookNodeStatus.PAUSED
        )
        candidates = paused
        if not candidates:
            candidates = sorted(
                node.id
                for node in playbook.nodes
                if record.node_states[node.id] is PlaybookNodeStatus.PENDING
                and all(
                    record.node_states[dependency]
                    is PlaybookNodeStatus.COMPLETED
                    for dependency in node.depends_on
                )
            )
        if not candidates:
            if all(
                status is PlaybookNodeStatus.COMPLETED
                for status in record.node_states.values()
            ):
                completed = DurablePlaybookRun.model_validate(
                    record.model_copy(
                        update={
                            "status": PlaybookRunStatus.COMPLETED_VERIFIED,
                            "updated_at": as_of,
                            "pause_reason": None,
                        }
                    ).model_dump(mode="python")
                )
                return self.store.replace(record, completed)
            raise SecurityError("effectful playbook has no safe deterministic next node")

        node = nodes_by_id[candidates[0]]
        resumed = record.node_states[node.id] is PlaybookNodeStatus.PAUSED
        running_states = dict(record.node_states)
        running_states[node.id] = PlaybookNodeStatus.RUNNING
        running_record = DurablePlaybookRun.model_validate(
            record.model_copy(
                update={
                    "status": PlaybookRunStatus.RUNNING,
                    "node_states": running_states,
                    "updated_at": as_of,
                    "pause_reason": None,
                }
            ).model_dump(mode="python")
        )
        running_record = self.store.replace(record, running_record)
        try:
            outcome = await self.executors.executor(node.executor_id).execute(
                node,
                context,
                resumed=resumed,
            )
        except Exception:
            uncertain_states = dict(running_record.node_states)
            uncertain_states[node.id] = PlaybookNodeStatus.UNCERTAIN
            uncertain = DurablePlaybookRun.model_validate(
                running_record.model_copy(
                    update={
                        "status": PlaybookRunStatus.PAUSED_UNCERTAIN,
                        "node_states": uncertain_states,
                        "updated_at": as_of,
                        "pause_reason": "NODE_EXECUTION_UNCERTAIN",
                    }
                ).model_dump(mode="python")
            )
            return self.store.replace(running_record, uncertain)

        node_status, run_status, reason = {
            PlaybookNodeOutcome.COMPLETED: (
                PlaybookNodeStatus.COMPLETED,
                PlaybookRunStatus.RUNNING,
                None,
            ),
            PlaybookNodeOutcome.PAUSE_APPROVAL: (
                PlaybookNodeStatus.PAUSED,
                PlaybookRunStatus.AWAITING_APPROVAL,
                "EXTERNAL_APPROVAL_REQUIRED",
            ),
            PlaybookNodeOutcome.PAUSE_OBSERVATION: (
                PlaybookNodeStatus.PAUSED,
                PlaybookRunStatus.AWAITING_OBSERVATION,
                "PROVIDER_OBSERVATION_PENDING",
            ),
            PlaybookNodeOutcome.UNCERTAIN: (
                PlaybookNodeStatus.UNCERTAIN,
                PlaybookRunStatus.PAUSED_UNCERTAIN,
                "NODE_RESULT_UNCERTAIN",
            ),
            PlaybookNodeOutcome.MANUAL_HANDOFF: (
                PlaybookNodeStatus.MANUAL_HANDOFF,
                PlaybookRunStatus.MANUAL_HANDOFF,
                "MANUAL_HANDOFF_REQUIRED",
            ),
            PlaybookNodeOutcome.COMPENSATION_PROPOSAL: (
                PlaybookNodeStatus.COMPENSATION_REQUIRED,
                PlaybookRunStatus.COMPENSATION_REQUIRED,
                "SEPARATE_COMPENSATION_PLAN_REQUIRED",
            ),
        }[outcome]
        node_states = dict(running_record.node_states)
        node_states[node.id] = node_status
        updated = DurablePlaybookRun.model_validate(
            running_record.model_copy(
                update={
                    "status": run_status,
                    "node_states": node_states,
                    "updated_at": as_of,
                    "pause_reason": reason,
                }
            ).model_dump(mode="python")
        )
        return self.store.replace(running_record, updated)

