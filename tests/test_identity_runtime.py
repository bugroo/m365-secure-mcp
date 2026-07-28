from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp.change_safe import ChangeSafeOperator
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_compiler import load_identity_candidate
from m365_secure_mcp.contract_manifest import ContractManifestV2, canonical_json
from m365_secure_mcp.identity_operations import (
    GroupProtectionEvidence,
    SkuCapacityEvidence,
    UserProtectionEvidence,
)
from m365_secure_mcp.identity_runtime import build_identity_runtime
from m365_secure_mcp.operations import OperationStatus
from m365_secure_mcp.operator_authority import (
    ApprovalReplayStore,
    ApprovalTrustRegistry,
    ExternalOperatorApprovalBroker,
    OperatorApprovalGrant,
    sign_operator_approval,
)
from m365_secure_mcp.operator_lifecycle import DurableOperationStore
from m365_secure_mcp.recovery import RecoveryCapsuleStore

from .operator_helpers import (
    DEPLOYMENT_NAMESPACE,
    NOW,
    OPERATOR_ID,
    TENANT_ID,
    USER_ID,
    authority_record,
    synthetic_governance,
)

GROUP_ID = UUID("44444444-4444-4444-8444-444444444444")
SKU_ID = UUID("55555555-5555-4555-8555-555555555555")
ROOT = Path(__file__).resolve().parents[1]


class RuntimeBackend:
    def __init__(self) -> None:
        self.enabled = True
        self.writes = 0

    async def read_user(self, user_id: UUID) -> UserProtectionEvidence:
        assert user_id == USER_ID
        return UserProtectionEvidence(
            user_id=user_id,
            user_type="Member",
            account_enabled=self.enabled,
            on_premises_sync_enabled=False,
            usage_location="DE",
            active_role_assignments=0,
            active_role_schedule_instances=0,
            eligible_role_schedule_instances=0,
            role_assignable_group_memberships=0,
            evidence_complete=True,
        )

    async def read_group(self, group_id: UUID) -> GroupProtectionEvidence:
        return GroupProtectionEvidence(
            group_id=group_id,
            dynamic=False,
            role_assignable=False,
            evidence_complete=True,
        )

    async def membership_exists(self, group_id: UUID, user_id: UUID) -> bool:
        return False

    async def read_sku(self, sku_id: UUID) -> SkuCapacityEvidence:
        return SkuCapacityEvidence(
            sku_id=sku_id,
            enabled_units=1,
            consumed_units=0,
            service_plan_ids=(),
            evidence_complete=True,
        )

    async def revoke_sessions(self, user_id: UUID) -> bool:
        self.writes += 1
        return True

    async def set_account_enabled(self, user_id: UUID, enabled: bool) -> None:
        self.enabled = enabled
        self.writes += 1

    async def add_membership(self, group_id: UUID, user_id: UUID) -> None:
        self.writes += 1

    async def remove_membership(self, group_id: UUID, user_id: UUID) -> None:
        self.writes += 1

    async def set_direct_license(
        self,
        user_id: UUID,
        sku_id: UUID,
        *,
        assigned: bool,
        disabled_service_plan_ids: tuple[UUID, ...],
    ) -> None:
        self.writes += 1


class VerifiedPolicyStub:
    def __init__(self, policy) -> None:
        self.policy = policy

    def refresh(self):
        return self


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _write_private(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value))
    path.chmod(0o600)


def _settings(root: Path) -> Settings:
    return Settings(
        tenant_id=str(TENANT_ID),
        client_id="99999999-9999-4999-8999-999999999999",
        profile="read",
        modules="profile",
        allowed_user_object_ids=str(OPERATOR_ID),
        token_cache_mode="memory",  # noqa: S106
        audit_log_path=root / "audit.jsonl",
        idempotency_db_path=root / "idempotency.sqlite3",
        recovery_capsule_path=root / "capsules.jsonl",
    )


@pytest.mark.asyncio
async def test_runtime_pauses_for_external_approval_then_executes_once(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "identity-approver",
        "identity-person",
        "identity-key-2026",
        "identity-operations",
        signer,
    )
    registry = ApprovalTrustRegistry(authorities=(authority,))
    registry_path = root / "trust.json"
    _write_private(registry_path, registry.model_dump(mode="json"))
    broker = ExternalOperatorApprovalBroker(
        directory=root / "approvals",
        trust_registry_path=registry_path,
    )
    candidate = load_identity_candidate(ROOT)
    contract = candidate.contract("entra.user.account_state.set")
    manifest = ContractManifestV2(
        schema_version="2.0",
        product="m365-secure-mcp",
        contracts=[contract],
    )
    policy, _ = synthetic_governance(contract, (authority,))
    settings = _settings(root)
    backend = RuntimeBackend()
    runtime = build_identity_runtime(
        manifest=manifest,
        governance=VerifiedPolicyStub(policy),  # type: ignore[arg-type]
        graph=SimpleNamespace(),  # type: ignore[arg-type]
        operator=ChangeSafeOperator(
            tenant_id=str(TENANT_ID),
            deployment_namespace=DEPLOYMENT_NAMESPACE,
        ),
        approval_broker=broker,
        replay_store=ApprovalReplayStore(
            root / "replay.sqlite3",
            DEPLOYMENT_NAMESPACE,
        ),
        lifecycle_store=DurableOperationStore(
            root / "lifecycle.sqlite3",
            DEPLOYMENT_NAMESPACE,
        ),
        recovery=RecoveryCapsuleStore(settings),
        backend=backend,
    )
    idempotency_key = uuid4()
    first = await runtime.invoke(
        operation_id=contract.id,
        intended_operator_id=OPERATOR_ID,
        target_user_id=USER_ID,
        parameters={
            "account_enabled": False,
            "user_id": str(USER_ID),
        },
        idempotency_key=idempotency_key,
        as_of=NOW,
    )
    assert first.status is OperationStatus.AWAITING_APPROVAL
    assert backend.writes == 0
    request = broker.load_request(
        UUID(first.approval_request_reference.removeprefix("approval-request:"))
    )
    assert request is not None
    approval = sign_operator_approval(
        OperatorApprovalGrant(
            approval_id=uuid4(),
            plan_digest=request.plan_digest,
            authority_id=authority.authority_id,
            tenant_id=TENANT_ID,
            profile="selected-write",
            intended_operator_id=OPERATOR_ID,
            issued_at=NOW + timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=2),
        ),
        signer,
        key_id=authority.key_id,
    )
    approval_path = (
        root
        / "approvals"
        / f"{request.plan.plan_id}.{authority.authority_id}.approval.json"
    )
    _write_private(approval_path, approval.model_dump(mode="json"))
    completed = await runtime.invoke(
        operation_id=contract.id,
        intended_operator_id=OPERATOR_ID,
        target_user_id=USER_ID,
        parameters={
            "account_enabled": False,
            "user_id": str(USER_ID),
        },
        idempotency_key=idempotency_key,
        as_of=NOW + timedelta(seconds=2),
    )
    assert completed.status is OperationStatus.EXECUTED_VERIFIED
    assert completed.receipt_reference is not None
    assert completed.change_record_reference is not None
    assert backend.writes == 1
    replay = await runtime.invoke(
        operation_id=contract.id,
        intended_operator_id=OPERATOR_ID,
        target_user_id=USER_ID,
        parameters={
            "account_enabled": False,
            "user_id": str(USER_ID),
        },
        idempotency_key=idempotency_key,
        as_of=NOW + timedelta(seconds=3),
    )
    assert replay.status is OperationStatus.EXECUTED_VERIFIED
    assert backend.writes == 1
    public = json.dumps(replay.model_dump(mode="json"))
    assert str(TENANT_ID) not in public
    assert str(USER_ID) not in public
    assert str(OPERATOR_ID) not in public


@pytest.mark.asyncio
async def test_idempotency_key_cannot_be_rebound_to_another_target(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "identity-approver",
        "identity-person",
        "identity-key-2026",
        "identity-operations",
        signer,
    )
    registry_path = root / "trust.json"
    _write_private(
        registry_path,
        ApprovalTrustRegistry(authorities=(authority,)).model_dump(mode="json"),
    )
    candidate = load_identity_candidate(ROOT)
    contract = candidate.contract("entra.user.account_state.set")
    manifest = ContractManifestV2(
        schema_version="2.0",
        product="m365-secure-mcp",
        contracts=[contract],
    )
    policy, _ = synthetic_governance(contract, (authority,))
    runtime = build_identity_runtime(
        manifest=manifest,
        governance=VerifiedPolicyStub(policy),  # type: ignore[arg-type]
        graph=SimpleNamespace(),  # type: ignore[arg-type]
        operator=ChangeSafeOperator(
            tenant_id=str(TENANT_ID),
            deployment_namespace=DEPLOYMENT_NAMESPACE,
        ),
        approval_broker=ExternalOperatorApprovalBroker(
            directory=root / "approvals",
            trust_registry_path=registry_path,
        ),
        replay_store=ApprovalReplayStore(
            root / "replay.sqlite3",
            DEPLOYMENT_NAMESPACE,
        ),
        lifecycle_store=DurableOperationStore(
            root / "lifecycle.sqlite3",
            DEPLOYMENT_NAMESPACE,
        ),
        recovery=RecoveryCapsuleStore(_settings(root)),
        backend=RuntimeBackend(),
    )
    key = uuid4()
    await runtime.invoke(
        operation_id=contract.id,
        intended_operator_id=OPERATOR_ID,
        target_user_id=USER_ID,
        parameters={"account_enabled": False, "user_id": str(USER_ID)},
        idempotency_key=key,
        as_of=NOW,
    )
    other = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    with pytest.raises(Exception, match="another exact plan"):
        await runtime.invoke(
            operation_id=contract.id,
            intended_operator_id=OPERATOR_ID,
            target_user_id=other,
            parameters={"account_enabled": False, "user_id": str(other)},
            idempotency_key=key,
            as_of=NOW + timedelta(seconds=1),
        )
