from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from m365_secure_mcp.contract_compiler import load_identity_candidate
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    effect_model_digest,
    load_active_identity_manifest,
    sha256_digest,
)
from m365_secure_mcp.governance import GovernanceResources, ResourceFenceType
from m365_secure_mcp.identity_operations import (
    GroupProtectionEvidence,
    IdentityOperationProvider,
    SkuCapacityEvidence,
    UserProtectionEvidence,
)
from m365_secure_mcp.operator_authority import (
    CompensationDeclaration,
    ExpectedPostcondition,
    OperatorPlan,
    PlanParameter,
    PreconditionBinding,
    TargetReference,
)
from m365_secure_mcp.operator_lifecycle import (
    ProviderExecutionKind,
    ProviderObservationKind,
)
from m365_secure_mcp.security import SecurityError

ROOT = Path(__file__).resolve().parents[1]
TENANT = UUID("11111111-1111-4111-8111-111111111111")
USER = UUID("22222222-2222-4222-8222-222222222222")
GROUP = UUID("33333333-3333-4333-8333-333333333333")
SKU = UUID("44444444-4444-4444-8444-444444444444")
PLAN_A = UUID("55555555-5555-4555-8555-555555555555")
PLAN_B = UUID("66666666-6666-4666-8666-666666666666")
NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


class FakeIdentityBackend:
    def __init__(self) -> None:
        self.user = UserProtectionEvidence(
            user_id=USER,
            user_type="Member",
            account_enabled=True,
            on_premises_sync_enabled=False,
            usage_location="DE",
            active_role_assignments=0,
            active_role_schedule_instances=0,
            eligible_role_schedule_instances=0,
            role_assignable_group_memberships=0,
            evidence_complete=True,
        )
        self.group = GroupProtectionEvidence(
            group_id=GROUP,
            dynamic=False,
            role_assignable=False,
            evidence_complete=True,
        )
        self.sku = SkuCapacityEvidence(
            sku_id=SKU,
            enabled_units=10,
            consumed_units=2,
            service_plan_ids=(PLAN_A, PLAN_B),
            evidence_complete=True,
        )
        self.member = False
        self.revoked = False
        self.calls: list[str] = []

    async def read_user(self, user_id: UUID) -> UserProtectionEvidence:
        assert user_id == USER
        return self.user

    async def read_group(self, group_id: UUID) -> GroupProtectionEvidence:
        assert group_id == GROUP
        return self.group

    async def membership_exists(self, group_id: UUID, user_id: UUID) -> bool:
        assert (group_id, user_id) == (GROUP, USER)
        return self.member

    async def read_sku(self, sku_id: UUID) -> SkuCapacityEvidence:
        assert sku_id == SKU
        return self.sku

    async def revoke_sessions(self, user_id: UUID) -> bool:
        assert user_id == USER
        self.revoked = True
        self.calls.append("revoke")
        return True

    async def set_account_enabled(self, user_id: UUID, enabled: bool) -> None:
        assert user_id == USER
        self.user = self.user.model_copy(update={"account_enabled": enabled})
        self.calls.append("account")

    async def add_membership(self, group_id: UUID, user_id: UUID) -> None:
        assert (group_id, user_id) == (GROUP, USER)
        self.member = True
        self.calls.append("membership_add")

    async def remove_membership(self, group_id: UUID, user_id: UUID) -> None:
        assert (group_id, user_id) == (GROUP, USER)
        self.member = False
        self.calls.append("membership_remove")

    async def set_direct_license(
        self,
        user_id: UUID,
        sku_id: UUID,
        *,
        assigned: bool,
        disabled_service_plan_ids: tuple[UUID, ...],
    ) -> None:
        assert (user_id, sku_id) == (USER, SKU)
        assert disabled_service_plan_ids == (PLAN_A,)
        direct = {item for item in self.user.direct_sku_ids}
        if assigned:
            direct.add(SKU)
        else:
            direct.discard(SKU)
        self.user = self.user.model_copy(
            update={"direct_sku_ids": tuple(sorted(direct, key=str))}
        )
        self.calls.append("license")


def _resources(*, protected: bool = False) -> GovernanceResources:
    return GovernanceResources(
        tenants=[TENANT],
        users=[USER],
        groups=[GROUP],
        protected_user_ids=[USER] if protected else [],
        protected_group_ids=[],
        allowed_sku_ids=[SKU],
        allowed_service_plan_ids={SKU: [PLAN_A, PLAN_B]},
    )


def _plan(
    operation_id: str,
    parameters: tuple[PlanParameter, ...] = (),
) -> OperatorPlan:
    contract = load_identity_candidate(ROOT).contract(operation_id)
    compensation = CompensationDeclaration(
        classification=contract.compensation,
        manual_handoff_id=(
            "manual.session_revocation_review"
            if contract.compensation is CompensationClass.NOT_COMPENSATABLE
            else None
        ),
    )
    return OperatorPlan(
        plan_id=uuid4(),
        nonce=uuid4(),
        operation_id=operation_id,
        contract_id=operation_id,
        contract_digest=sha256_digest(contract),
        contract_manifest_digest=sha256_digest(load_identity_candidate(ROOT)),
        effect_model_digest=effect_model_digest(),
        policy_digest="sha256:" + ("1" * 64),
        tenant_id=TENANT,
        deployment_namespace="0123456789abcdef",
        profile="selected-write",
        intended_operator_id=UUID("77777777-7777-4777-8777-777777777777"),
        effect=contract.effect,
        risk_tier="T2",
        authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
        target=TargetReference(
            resource_type=ResourceFenceType.USER,
            object_id=USER,
            opaque_reference="target:" + ("2" * 64),
        ),
        parameters=parameters,
        preconditions=(
            PreconditionBinding(
                check_id="identity.complete_protected_snapshot",
                evidence_digest="sha256:" + ("3" * 64),
            ),
        ),
        expected_postcondition=ExpectedPostcondition(
            check_id="identity.expected_postcondition",
            expected_digest="sha256:" + ("4" * 64),
        ),
        verification=contract.verification,
        compensation=compensation,
        observation_timeout_seconds=60,
        maximum_observation_polls=2,
        created_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


async def _bound_plan(
    provider: IdentityOperationProvider,
    plan: OperatorPlan,
) -> OperatorPlan:
    bindings = await provider.preflight(plan)
    return OperatorPlan.model_validate(
        {**plan.model_dump(mode="python"), "preconditions": bindings}
    )


@pytest.mark.asyncio
async def test_session_revocation_is_accepted_not_falsely_verified() -> None:
    backend = FakeIdentityBackend()
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id="entra.user.sessions.revoke",
    )
    plan = await _bound_plan(provider, _plan("entra.user.sessions.revoke"))
    result = await provider.execute(plan)
    assert result.kind is ProviderExecutionKind.ACCEPTED
    assert result.observation_handle is not None
    observed = await provider.observe(result.observation_handle)
    assert observed.kind is ProviderObservationKind.PENDING
    assert backend.calls == ["revoke"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation_id", "parameters", "expected_call"),
    [
        (
            "entra.user.account_state.set",
            (PlanParameter(name="account_enabled", value=False),),
            "account",
        ),
        (
            "entra.group.user_membership.add",
            (PlanParameter(name="group_id", value=str(GROUP)),),
            "membership_add",
        ),
        (
            "entra.user.direct_license.set",
            (
                PlanParameter(
                    name="disabled_service_plan_ids",
                    value=(str(PLAN_A),),
                ),
                PlanParameter(name="license_assigned", value=True),
                PlanParameter(name="sku_id", value=str(SKU)),
            ),
            "license",
        ),
    ],
)
async def test_identity_desired_state_operations_verify_postcondition(
    operation_id: str,
    parameters: tuple[PlanParameter, ...],
    expected_call: str,
) -> None:
    backend = FakeIdentityBackend()
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id=operation_id,
    )
    plan = await _bound_plan(provider, _plan(operation_id, parameters))
    result = await provider.execute(plan)
    assert result.kind is ProviderExecutionKind.VERIFIED
    assert backend.calls == [expected_call]


@pytest.mark.asyncio
async def test_membership_remove_uses_inverse_desired_state() -> None:
    backend = FakeIdentityBackend()
    backend.member = True
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id="entra.group.user_membership.remove",
    )
    plan = await _bound_plan(
        provider,
        _plan(
            "entra.group.user_membership.remove",
            (PlanParameter(name="group_id", value=str(GROUP)),),
        ),
    )
    result = await provider.execute(plan)
    assert result.kind is ProviderExecutionKind.VERIFIED
    assert backend.calls == ["membership_remove"]
    assert backend.member is False


@pytest.mark.asyncio
async def test_already_satisfied_operation_is_verified_without_write() -> None:
    backend = FakeIdentityBackend()
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id="entra.user.account_state.set",
    )
    plan = await _bound_plan(
        provider,
        _plan(
            "entra.user.account_state.set",
            (PlanParameter(name="account_enabled", value=True),),
        ),
    )
    result = await provider.execute(plan)
    assert result.kind is ProviderExecutionKind.VERIFIED
    assert backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "update",
    [
        {"evidence_complete": False},
        {"user_type": "Guest"},
        {"on_premises_sync_enabled": True},
        {"active_role_assignments": 1},
        {"eligible_role_schedule_instances": 1},
        {"role_assignable_group_memberships": 1},
    ],
)
async def test_user_protection_evidence_fails_closed(update: dict[str, object]) -> None:
    backend = FakeIdentityBackend()
    backend.user = backend.user.model_copy(update=update)
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id="entra.user.sessions.revoke",
    )
    with pytest.raises(SecurityError, match="protection evidence"):
        await provider.preflight(_plan("entra.user.sessions.revoke"))


@pytest.mark.asyncio
async def test_governance_protected_user_fails_before_graph_write() -> None:
    backend = FakeIdentityBackend()
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(protected=True),
        operation_id="entra.user.sessions.revoke",
    )
    with pytest.raises(SecurityError, match="protected"):
        await provider.preflight(_plan("entra.user.sessions.revoke"))
    assert backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("group_update", [{"dynamic": True}, {"role_assignable": True}])
async def test_unsafe_group_fails_closed(group_update: dict[str, object]) -> None:
    backend = FakeIdentityBackend()
    backend.group = backend.group.model_copy(update=group_update)
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id="entra.group.user_membership.add",
    )
    with pytest.raises(SecurityError, match="group protection"):
        await provider.preflight(
            _plan(
                "entra.group.user_membership.add",
                (PlanParameter(name="group_id", value=str(GROUP)),),
            )
        )


@pytest.mark.asyncio
async def test_inherited_license_is_never_removed() -> None:
    backend = FakeIdentityBackend()
    backend.user = backend.user.model_copy(update={"inherited_sku_ids": (SKU,)})
    provider = IdentityOperationProvider(
        backend=backend,
        resources=_resources(),
        operation_id="entra.user.direct_license.set",
    )
    plan = _plan(
        "entra.user.direct_license.set",
        (
            PlanParameter(
                name="disabled_service_plan_ids",
                value=(str(PLAN_A),),
            ),
            PlanParameter(name="license_assigned", value=False),
            PlanParameter(name="sku_id", value=str(SKU)),
        ),
    )
    with pytest.raises(SecurityError, match="license preconditions"):
        await provider.preflight(plan)
    assert backend.calls == []


def test_candidate_catalog_is_absent_until_productive_signature() -> None:
    assert load_active_identity_manifest() is None
