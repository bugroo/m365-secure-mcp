from __future__ import annotations

import json
from collections import deque
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from m365_secure_mcp.contract_manifest import VerificationMode
from m365_secure_mcp.operator_authority import OperatorPlan, PreconditionBinding
from m365_secure_mcp.operator_lifecycle import (
    DurableOperationStore,
    DurableOperatorLifecycle,
    OperationProvider,
    OperatorLifecycleStatus,
    ProviderExecutionKind,
    ProviderExecutionResult,
    ProviderObservationKind,
    ProviderObservationResult,
    ProviderTransportError,
)
from m365_secure_mcp.security import SecurityError

from .operator_helpers import (
    DEPLOYMENT_NAMESPACE,
    NOW,
    operator_context,
)


class SyntheticProvider(OperationProvider):
    def __init__(
        self,
        *,
        execution: ProviderExecutionResult | Exception,
        observations: tuple[ProviderObservationResult, ...] = (),
        preconditions: tuple[PreconditionBinding, ...] | None = None,
        cancellation: ProviderObservationResult | None = None,
    ) -> None:
        self.execution = execution
        self.observations = deque(observations)
        self.preconditions = preconditions
        self.cancellation = cancellation
        self.execute_count = 0
        self.observe_count = 0
        self.cancel_count = 0

    async def preflight(
        self,
        plan: OperatorPlan,
    ) -> tuple[PreconditionBinding, ...]:
        return self.preconditions or plan.preconditions

    async def execute(self, plan: OperatorPlan) -> ProviderExecutionResult:
        del plan
        self.execute_count += 1
        if isinstance(self.execution, Exception):
            raise self.execution
        return self.execution

    async def observe(
        self,
        observation_handle: str,
    ) -> ProviderObservationResult:
        assert observation_handle.startswith("observation:")
        self.observe_count += 1
        if not self.observations:
            raise RuntimeError("synthetic observation exhausted")
        return self.observations.popleft()

    @property
    def supports_cancellation(self) -> bool:
        return self.cancellation is not None

    async def cancel(
        self,
        observation_handle: str,
    ) -> ProviderObservationResult:
        assert observation_handle.startswith("observation:")
        self.cancel_count += 1
        if self.cancellation is None:
            raise RuntimeError("synthetic provider does not support cancellation")
        return self.cancellation


def _execution(kind: ProviderExecutionKind) -> ProviderExecutionResult:
    return ProviderExecutionResult(
        kind=kind,
        evidence_reference="evidence:" + ("a" * 32),
        observation_handle=(
            "observation:" + ("b" * 32)
            if kind is ProviderExecutionKind.ACCEPTED
            else None
        ),
    )


def _observation(kind: ProviderObservationKind) -> ProviderObservationResult:
    return ProviderObservationResult(
        kind=kind,
        evidence_reference="evidence:" + ("c" * 32),
    )


def _lifecycle(tmp_path: Path) -> DurableOperatorLifecycle:
    return DurableOperatorLifecycle(
        DurableOperationStore(
            tmp_path / "lifecycle" / "operations.sqlite3",
            DEPLOYMENT_NAMESPACE,
        )
    )


@pytest.mark.asyncio
async def test_synchronous_verified_operation_executes_once(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    lifecycle = _lifecycle(tmp_path)
    provider = SyntheticProvider(execution=_execution(ProviderExecutionKind.VERIFIED))
    operation_id = uuid4()

    record = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=lifecycle,
        provider=provider,
        operation_id=operation_id,
        as_of=NOW,
    )
    assert record.status is OperatorLifecycleStatus.COMPLETED
    assert provider.execute_count == 1

    restarted = _lifecycle(tmp_path)
    duplicate = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=(),
        validator=validator,
        lifecycle=restarted,
        provider=provider,
        operation_id=operation_id,
        as_of=NOW + timedelta(seconds=1),
    )
    assert duplicate.status is OperatorLifecycleStatus.COMPLETED
    assert provider.execute_count == 1


@pytest.mark.asyncio
async def test_async_acceptance_is_not_verification_and_resumes_after_restart(
    tmp_path: Path,
) -> None:
    operator, plan, governance, validator, approvals = operator_context(
        tmp_path,
        verification=VerificationMode.ASYNC_STATUS,
    )
    provider = SyntheticProvider(
        execution=_execution(ProviderExecutionKind.ACCEPTED),
        observations=(
            _observation(ProviderObservationKind.PENDING),
            _observation(ProviderObservationKind.VERIFIED),
        ),
    )
    operation_id = uuid4()
    accepted = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=operation_id,
        as_of=NOW,
    )
    assert accepted.status is OperatorLifecycleStatus.EXECUTED_ACCEPTED
    assert accepted.observation_handle is not None

    observing = await _lifecycle(tmp_path).observe(
        operation_id=operation_id,
        provider=provider,
        as_of=NOW + timedelta(seconds=10),
    )
    assert observing.status is OperatorLifecycleStatus.OBSERVING
    completed = await _lifecycle(tmp_path).observe(
        operation_id=operation_id,
        provider=provider,
        as_of=NOW + timedelta(seconds=20),
    )
    assert completed.status is OperatorLifecycleStatus.COMPLETED
    assert provider.execute_count == 1
    assert provider.observe_count == 2


@pytest.mark.asyncio
async def test_accepted_operation_times_out_to_manual_review(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(
        tmp_path,
        verification=VerificationMode.ASYNC_STATUS,
        observation_timeout_seconds=30,
        maximum_observation_polls=1,
    )
    provider = SyntheticProvider(execution=_execution(ProviderExecutionKind.ACCEPTED))
    operation_id = uuid4()
    await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=operation_id,
        as_of=NOW,
    )
    record = await _lifecycle(tmp_path).observe(
        operation_id=operation_id,
        provider=provider,
        as_of=NOW + timedelta(seconds=30),
    )
    assert record.status is OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED
    assert record.terminal_reason == "OBSERVATION_LIMIT_REACHED"
    assert provider.observe_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("commit_possible", "expected"),
    [
        (False, OperatorLifecycleStatus.COMPLETED),
        (True, OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED),
    ],
)
async def test_transport_failures_preserve_commit_ambiguity(
    tmp_path: Path,
    commit_possible: bool,
    expected: OperatorLifecycleStatus,
) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    provider = SyntheticProvider(
        execution=ProviderTransportError(
            "synthetic transport failure",
            commit_possible=commit_possible,
        )
    )
    operation_id = uuid4()
    record = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=operation_id,
        as_of=NOW,
    )
    assert record.status is expected
    assert provider.execute_count == 1

    replay = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=(),
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=operation_id,
        as_of=NOW + timedelta(seconds=1),
    )
    assert replay.status is expected
    assert provider.execute_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (ProviderExecutionKind.FAILED_CONFIRMED, OperatorLifecycleStatus.COMPLETED),
        (
            ProviderExecutionKind.UNCERTAIN,
            OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
        ),
    ],
)
async def test_provider_outcome_preserves_failure_certainty(
    tmp_path: Path,
    kind: ProviderExecutionKind,
    expected: OperatorLifecycleStatus,
) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    provider = SyntheticProvider(execution=_execution(kind))
    record = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=uuid4(),
        as_of=NOW,
    )
    assert record.status is expected


@pytest.mark.asyncio
async def test_restart_from_executing_never_duplicates_effect(tmp_path: Path) -> None:
    _, plan, _, _, _ = operator_context(tmp_path)
    lifecycle = _lifecycle(tmp_path)
    operation_id = uuid4()
    record = lifecycle.store.ensure(
        plan,
        operation_id=operation_id,
        as_of=NOW,
        observation_deadline=NOW + timedelta(minutes=1),
        max_polls=2,
    )
    record = lifecycle.store.transition(
        record,
        OperatorLifecycleStatus.AWAITING_APPROVAL,
        as_of=NOW,
    )
    record = lifecycle.store.transition(
        record,
        OperatorLifecycleStatus.AUTHORIZED,
        as_of=NOW,
    )
    lifecycle.store.transition(
        record,
        OperatorLifecycleStatus.EXECUTING,
        as_of=NOW,
    )
    provider = SyntheticProvider(execution=_execution(ProviderExecutionKind.VERIFIED))

    resumed = await _lifecycle(tmp_path).execute(
        plan=plan,
        operation_id=operation_id,
        provider=provider,
        as_of=NOW + timedelta(seconds=1),
        authorized=True,
        async_allowed=False,
    )
    assert resumed.status is OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED
    assert provider.execute_count == 0


@pytest.mark.asyncio
async def test_restart_after_atomic_approval_burn_can_promote_exact_plan(
    tmp_path: Path,
) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    lifecycle = _lifecycle(tmp_path)
    operation_id = uuid4()
    record = lifecycle.store.ensure(
        plan,
        operation_id=operation_id,
        as_of=NOW,
        observation_deadline=NOW + timedelta(minutes=1),
        max_polls=2,
    )
    lifecycle.store.transition(
        record,
        OperatorLifecycleStatus.AWAITING_APPROVAL,
        as_of=NOW,
    )
    validator.validate(
        plan,
        governance,
        approvals,
        as_of=NOW,
        consume=True,
    )
    provider = SyntheticProvider(execution=_execution(ProviderExecutionKind.VERIFIED))

    completed = await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=operation_id,
        as_of=NOW + timedelta(seconds=1),
    )
    assert completed.status is OperatorLifecycleStatus.COMPLETED
    assert provider.execute_count == 1


def test_changed_digest_prevents_resume(tmp_path: Path) -> None:
    _, plan, _, _, _ = operator_context(tmp_path)
    lifecycle = _lifecycle(tmp_path)
    operation_id = uuid4()
    lifecycle.store.ensure(
        plan,
        operation_id=operation_id,
        as_of=NOW,
        observation_deadline=NOW + timedelta(minutes=1),
        max_polls=2,
    )
    changed = plan.model_copy(
        update={"policy_digest": "sha256:" + ("0" * 64)}
    )
    with pytest.raises(SecurityError, match="changed digests"):
        lifecycle.store.ensure(
            changed,
            operation_id=operation_id,
            as_of=NOW,
            observation_deadline=NOW + timedelta(minutes=1),
            max_polls=2,
        )


@pytest.mark.asyncio
async def test_toctou_change_blocks_before_provider_effect(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    provider = SyntheticProvider(
        execution=_execution(ProviderExecutionKind.VERIFIED),
        preconditions=(
            PreconditionBinding(
                check_id="target.not_protected",
                evidence_digest="sha256:" + ("0" * 64),
            ),
        ),
    )
    with pytest.raises(SecurityError, match="TOCTOU"):
        await operator.execute_effectful(
            plan=plan,
            governance=governance,
            approvals=approvals,
            validator=validator,
            lifecycle=_lifecycle(tmp_path),
            provider=provider,
            operation_id=uuid4(),
            as_of=NOW,
        )
    assert provider.execute_count == 0


@pytest.mark.asyncio
async def test_safe_provider_cancellation_requires_explicit_support(
    tmp_path: Path,
) -> None:
    operator, plan, governance, validator, approvals = operator_context(
        tmp_path,
        verification=VerificationMode.ASYNC_STATUS,
    )
    provider = SyntheticProvider(
        execution=_execution(ProviderExecutionKind.ACCEPTED),
        cancellation=_observation(ProviderObservationKind.FAILED_CONFIRMED),
    )
    operation_id = uuid4()
    await operator.execute_effectful(
        plan=plan,
        governance=governance,
        approvals=approvals,
        validator=validator,
        lifecycle=_lifecycle(tmp_path),
        provider=provider,
        operation_id=operation_id,
        as_of=NOW,
    )
    cancelled = await _lifecycle(tmp_path).cancel(
        operation_id=operation_id,
        provider=provider,
        as_of=NOW + timedelta(seconds=1),
    )
    assert cancelled.status is OperatorLifecycleStatus.COMPLETED
    assert cancelled.terminal_reason == "PROVIDER_CANCELLATION_CONFIRMED"


def test_public_projection_contains_only_opaque_references(tmp_path: Path) -> None:
    _, plan, _, _, _ = operator_context(tmp_path)
    lifecycle = _lifecycle(tmp_path)
    operation_id = UUID("44444444-4444-4444-8444-444444444444")
    record = lifecycle.store.ensure(
        plan,
        operation_id=operation_id,
        as_of=NOW,
        observation_deadline=NOW + timedelta(minutes=1),
        max_polls=2,
    )
    public = lifecycle.public(record)
    payload = json.dumps(public.model_dump(mode="json"), sort_keys=True)
    assert str(plan.tenant_id) not in payload
    assert str(plan.target.object_id) not in payload
    assert str(plan.intended_operator_id) not in payload
    assert "desired_state" not in payload
    assert "person-" not in payload
