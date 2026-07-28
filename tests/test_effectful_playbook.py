from __future__ import annotations

import base64
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from m365_secure_mcp.change_safe import ChangeSafeOperator
from m365_secure_mcp.contract_manifest import sha256_digest
from m365_secure_mcp.effectful_playbook import (
    DurablePlaybookStore,
    EffectfulExecutorRegistry,
    EffectfulPlaybookExecutor,
    EffectfulPlaybookRunner,
    EffectfulRunContext,
    PlaybookNodeOutcome,
    PlaybookNodeStatus,
    PlaybookRunStatus,
)
from m365_secure_mcp.playbook_manifest import (
    EffectfulExecutorId,
    EffectfulNodeKind,
    EffectfulPlaybookManifest,
    verify_effectful_playbook_manifest,
)
from m365_secure_mcp.security import SecurityError

from .operator_helpers import (
    DEPLOYMENT_NAMESPACE,
    NOW,
    operator_context,
    signed_effectful_fixture,
)


class WorkflowExecutor(EffectfulPlaybookExecutor):
    def __init__(
        self,
        *,
        operator: ChangeSafeOperator,
        plan,
        governance,
        validator,
        approvals=(),
        pause_observation: bool = False,
        uncertain_write: bool = False,
    ) -> None:
        self.operator = operator
        self.plan = plan
        self.governance = governance
        self.validator = validator
        self.approvals = approvals
        self.pause_observation = pause_observation
        self.uncertain_write = uncertain_write
        self.calls: dict[str, int] = {}

    async def execute(self, node, context, *, resumed: bool):
        assert context.plan_digest == self.plan.digest
        self.calls[node.id] = self.calls.get(node.id, 0) + 1
        if node.kind is EffectfulNodeKind.APPROVAL:
            required = 2 if self.plan.risk_tier == "T3" else 1
            if len(self.approvals) != required:
                return PlaybookNodeOutcome.PAUSE_APPROVAL
            self.operator.authorize_effectful_plan(
                plan=self.plan,
                governance=self.governance,
                approvals=self.approvals,
                validator=self.validator,
                as_of=NOW,
            )
            return PlaybookNodeOutcome.COMPLETED
        if node.kind is EffectfulNodeKind.WRITE and self.uncertain_write:
            return PlaybookNodeOutcome.UNCERTAIN
        if (
            node.kind is EffectfulNodeKind.OBSERVE
            and self.pause_observation
            and not resumed
        ):
            return PlaybookNodeOutcome.PAUSE_OBSERVATION
        if node.kind is EffectfulNodeKind.MANUAL_HANDOFF:
            return PlaybookNodeOutcome.MANUAL_HANDOFF
        return PlaybookNodeOutcome.COMPLETED


def _registry(executor: WorkflowExecutor) -> EffectfulExecutorRegistry:
    return EffectfulExecutorRegistry(
        {executor_id: executor for executor_id in EffectfulExecutorId}
    )


def _runner(tmp_path: Path, executor: WorkflowExecutor) -> EffectfulPlaybookRunner:
    return EffectfulPlaybookRunner(
        store=DurablePlaybookStore(
            tmp_path / "playbooks" / "runs.sqlite3",
            DEPLOYMENT_NAMESPACE,
        ),
        executors=_registry(executor),
    )


def _context(spec, verified, plan) -> EffectfulRunContext:
    return EffectfulRunContext(
        instance_id=uuid4(),
        playbook_id=spec.id,
        playbook_manifest_digest=verified.manifest_digest,
        playbook_digest=sha256_digest(spec),
        contract_manifest_digest=plan.contract_manifest_digest,
        effect_model_digest=plan.effect_model_digest,
        policy_digest=plan.policy_digest,
        plan_digest=plan.digest,
        contract_digest=plan.contract_digest,
        deployment_namespace=DEPLOYMENT_NAMESPACE,
    )


async def _advance_until(
    runner: EffectfulPlaybookRunner,
    verified,
    context: EffectfulRunContext,
    statuses: set[PlaybookRunStatus],
    *,
    limit: int = 30,
):
    record = None
    for offset in range(limit):
        record = await runner.step(
            verified_manifest=verified,
            context=context,
            as_of=NOW + timedelta(seconds=offset),
        )
        if record.status in statuses:
            return record
    raise AssertionError(f"playbook did not reach {statuses}; last={record}")


def test_effectful_manifest_signature_is_required_and_exact(tmp_path: Path) -> None:
    _, plan, _, _, _ = operator_context(tmp_path)
    _, manifest, signature, signer, verified = signed_effectful_fixture(plan=plan)
    assert verified.manifest_digest == sha256_digest(manifest)

    tampered = manifest.model_copy(
        update={
            "playbooks": [
                manifest.playbooks[0].model_copy(
                    update={"description": "A tampered synthetic workflow description."}
                )
            ]
        }
    )
    with pytest.raises(RuntimeError, match="digest mismatch"):
        verify_effectful_playbook_manifest(
            tampered,
            signature,
            trusted_key_id=signature.key_id,
            public_key=signer.public_key(),
        )
    with pytest.raises(RuntimeError, match="not trusted"):
        verify_effectful_playbook_manifest(
            manifest,
            signature,
            trusted_key_id="another-test-key",
            public_key=signer.public_key(),
        )


def test_effectful_manifest_rejects_unknown_executor_and_executable_fields(
    tmp_path: Path,
) -> None:
    _, plan, _, _, _ = operator_context(tmp_path)
    _, manifest, _, _, _ = signed_effectful_fixture(plan=plan)
    document = manifest.model_dump(mode="json")
    document["playbooks"][0]["nodes"][0]["executor_id"] = "python.eval"
    with pytest.raises(ValidationError):
        EffectfulPlaybookManifest.model_validate(document)
    document = manifest.model_dump(mode="json")
    document["playbooks"][0]["nodes"][0]["expression"] = "approve = True"
    with pytest.raises(ValidationError):
        EffectfulPlaybookManifest.model_validate(document)


@pytest.mark.asyncio
async def test_t2_playbook_pauses_for_external_approval_and_resumes(
    tmp_path: Path,
) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    spec, _, _, _, verified = signed_effectful_fixture(plan=plan)
    context = _context(spec, verified, plan)
    waiting_executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
    )
    waiting = await _advance_until(
        _runner(tmp_path, waiting_executor),
        verified,
        context,
        {PlaybookRunStatus.AWAITING_APPROVAL},
    )
    assert waiting.node_states["c_approval"] is PlaybookNodeStatus.PAUSED

    approved_executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=approvals,
    )
    completed = await _advance_until(
        _runner(tmp_path, approved_executor),
        verified,
        context,
        {PlaybookRunStatus.COMPLETED_VERIFIED},
    )
    assert completed.status is PlaybookRunStatus.COMPLETED_VERIFIED
    assert approved_executor.calls["c_approval"] == 1


@pytest.mark.asyncio
async def test_t3_playbook_requires_two_distinct_approvals(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(
        tmp_path,
        dual=True,
    )
    spec, _, _, _, verified = signed_effectful_fixture(plan=plan, dual=True)
    context = _context(spec, verified, plan)
    one_approval = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=approvals[:1],
    )
    waiting = await _advance_until(
        _runner(tmp_path, one_approval),
        verified,
        context,
        {PlaybookRunStatus.AWAITING_APPROVAL},
    )
    assert waiting.status is PlaybookRunStatus.AWAITING_APPROVAL

    dual_executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=approvals,
    )
    completed = await _advance_until(
        _runner(tmp_path, dual_executor),
        verified,
        context,
        {PlaybookRunStatus.COMPLETED_VERIFIED},
    )
    assert completed.status is PlaybookRunStatus.COMPLETED_VERIFIED


@pytest.mark.asyncio
async def test_async_node_resumes_after_process_restart(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    spec, _, _, _, verified = signed_effectful_fixture(plan=plan)
    context = _context(spec, verified, plan)
    first_executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=approvals,
        pause_observation=True,
    )
    paused = await _advance_until(
        _runner(tmp_path, first_executor),
        verified,
        context,
        {PlaybookRunStatus.AWAITING_OBSERVATION},
    )
    assert paused.node_states["e_observe"] is PlaybookNodeStatus.PAUSED

    restarted_executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=(),
        pause_observation=True,
    )
    completed = await _advance_until(
        _runner(tmp_path, restarted_executor),
        verified,
        context,
        {PlaybookRunStatus.COMPLETED_VERIFIED},
    )
    assert completed.status is PlaybookRunStatus.COMPLETED_VERIFIED
    assert restarted_executor.calls["e_observe"] == 1


@pytest.mark.asyncio
async def test_uncertain_write_halts_complete_dag(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    spec, _, _, _, verified = signed_effectful_fixture(plan=plan)
    context = _context(spec, verified, plan)
    executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=approvals,
        uncertain_write=True,
    )
    runner = _runner(tmp_path, executor)
    paused = await _advance_until(
        runner,
        verified,
        context,
        {PlaybookRunStatus.PAUSED_UNCERTAIN},
    )
    assert paused.node_states["d_write"] is PlaybookNodeStatus.UNCERTAIN
    assert paused.node_states["e_observe"] is PlaybookNodeStatus.PENDING
    unchanged = await runner.step(
        verified_manifest=verified,
        context=context,
        as_of=NOW + timedelta(minutes=1),
    )
    assert unchanged == paused
    assert executor.calls.get("e_observe") is None


@pytest.mark.asyncio
async def test_changed_policy_or_contract_digest_prevents_resume(
    tmp_path: Path,
) -> None:
    operator, plan, governance, validator, _ = operator_context(tmp_path)
    spec, _, _, _, verified = signed_effectful_fixture(plan=plan)
    context = _context(spec, verified, plan)
    executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
    )
    runner = _runner(tmp_path, executor)
    await runner.step(
        verified_manifest=verified,
        context=context,
        as_of=NOW,
    )
    changed = context.model_copy(
        update={"policy_digest": "sha256:" + ("0" * 64)}
    )
    with pytest.raises(SecurityError, match="changed trusted digests"):
        await _runner(tmp_path, executor).step(
            verified_manifest=verified,
            context=changed,
            as_of=NOW + timedelta(seconds=1),
        )


@pytest.mark.asyncio
async def test_manual_handoff_terminates_automated_progress(tmp_path: Path) -> None:
    operator, plan, governance, validator, approvals = operator_context(tmp_path)
    spec, _, _, _, verified = signed_effectful_fixture(
        plan=plan,
        manual_handoff=True,
    )
    context = _context(spec, verified, plan)
    executor = WorkflowExecutor(
        operator=operator,
        plan=plan,
        governance=governance,
        validator=validator,
        approvals=approvals,
    )
    runner = _runner(tmp_path, executor)
    handoff = await _advance_until(
        runner,
        verified,
        context,
        {PlaybookRunStatus.MANUAL_HANDOFF},
    )
    assert handoff.node_states["h_handoff"] is PlaybookNodeStatus.MANUAL_HANDOFF
    assert await runner.step(
        verified_manifest=verified,
        context=context,
        as_of=NOW + timedelta(minutes=1),
    ) == handoff


def test_signature_bytes_never_contain_test_private_key_material(tmp_path: Path) -> None:
    _, plan, _, _, _ = operator_context(tmp_path)
    _, manifest, signature, _, _ = signed_effectful_fixture(plan=plan)
    serialized = (
        str(manifest.model_dump(mode="json"))
        + str(signature.model_dump(mode="json"))
    )
    assert "PRIVATE KEY" not in serialized
    assert "BEGIN" not in base64.b64decode(
        signature.signature,
        validate=True,
    ).decode("latin1")

