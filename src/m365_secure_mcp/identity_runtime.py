"""Fail-closed runtime wiring for signed Identity schema-2.0 contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from .change_safe import ChangeSafeOperator
from .contract_manifest import (
    CompensationClass,
    ContractManifestV2,
    ContractSpecV2,
    VerificationMode,
    sha256_digest,
)
from .governance import (
    EffectiveOperationGovernance,
    GovernancePolicyV3,
    ResourceFenceType,
    VerifiedGovernancePolicy,
    resolve_operation_governance,
)
from .graph import GraphClient
from .identity_operations import (
    ClosedIdentityBackend,
    IdentityOperationProvider,
    MicrosoftGraphIdentityBackend,
)
from .operations import (
    ChangeRecord,
    GovernedReceipt,
    OperationStatus,
)
from .operator_authority import (
    ApprovalReplayStore,
    ApprovalSetValidator,
    CompensationDeclaration,
    ExpectedPostcondition,
    ExternalOperatorApprovalBroker,
    OperatorPlan,
    PlanParameter,
    PreconditionBinding,
    TargetReference,
)
from .operator_lifecycle import (
    DurableOperationRecord,
    DurableOperationStore,
    DurableOperatorLifecycle,
    OperatorLifecycleStatus,
)
from .recovery import RecoveryCapsuleStore
from .security import SecurityError


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IdentityOperationPublicResult(FrozenModel):
    """Minimized public projection; no tenant, target, plan or signer data."""

    status: OperationStatus
    operation_reference: str = Field(pattern=r"^operation:[0-9a-f-]{36}$")
    operator_action: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    safe_to_retry: bool
    evidence_reference: str | None = Field(
        default=None,
        pattern=r"^evidence:[0-9a-f]{32,64}$",
    )
    observation_reference: str | None = Field(
        default=None,
        pattern=r"^observation:[0-9a-f]{32,64}$",
    )
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{5,120}$")
    contract_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    verification: VerificationMode
    approval_request_reference: str = Field(
        pattern=r"^approval-request:[0-9a-f-]{36}$"
    )
    receipt_reference: str | None = Field(
        default=None,
        pattern=r"^receipt:[0-9a-f-]{36}$",
    )
    change_record_reference: str | None = Field(
        default=None,
        pattern=r"^change:[0-9a-f-]{36}$",
    )


@dataclass(frozen=True)
class IdentityRuntimeDependencies:
    manifest: ContractManifestV2
    governance: VerifiedGovernancePolicy
    backend: ClosedIdentityBackend
    operator: ChangeSafeOperator
    approval_broker: ExternalOperatorApprovalBroker
    approval_validator: ApprovalSetValidator
    lifecycle: DurableOperatorLifecycle
    recovery: RecoveryCapsuleStore


_TERMINAL_OR_EFFECT_STATES = frozenset(
    {
        OperatorLifecycleStatus.EXECUTED_ACCEPTED,
        OperatorLifecycleStatus.COMPLETED,
        OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
        OperatorLifecycleStatus.COMPENSATION_REQUIRED,
    }
)


def _opaque(prefix: str, material: str) -> str:
    return f"{prefix}:{hashlib.sha256(material.encode()).hexdigest()}"


def _lifecycle_operation_status(record: DurableOperationRecord) -> OperationStatus:
    if record.status in {
        OperatorLifecycleStatus.PLANNED,
        OperatorLifecycleStatus.AWAITING_APPROVAL,
        OperatorLifecycleStatus.AUTHORIZED,
    }:
        return OperationStatus.AWAITING_APPROVAL
    if record.status in {
        OperatorLifecycleStatus.EXECUTED_ACCEPTED,
        OperatorLifecycleStatus.OBSERVING,
    }:
        return OperationStatus.EXECUTED_ACCEPTED
    if record.status is OperatorLifecycleStatus.COMPLETED:
        if record.terminal_reason == "PLAN_WINDOW_EXPIRED":
            return OperationStatus.PLAN_EXPIRED
        if record.terminal_reason == "TOCTOU_PRECONDITION_CHANGED":
            return OperationStatus.BLOCKED_PRECONDITION
        if record.terminal_reason in {
            "PROVIDER_FAILED_CONFIRMED",
            "TRANSPORT_FAILURE_BEFORE_COMMIT",
        }:
            return OperationStatus.FAILED_RETRYABLE
        return OperationStatus.EXECUTED_VERIFIED
    if record.status in {
        OperatorLifecycleStatus.EXECUTED_UNCERTAIN,
        OperatorLifecycleStatus.TIMED_OUT,
        OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
        OperatorLifecycleStatus.COMPENSATION_REQUIRED,
    }:
        return OperationStatus.EXECUTED_UNCERTAIN
    return OperationStatus.BLOCKED_PRECONDITION


class IdentityContractRuntime:
    """Resolve, plan and execute only one of the signed fixed Identity contracts."""

    def __init__(self, dependencies: IdentityRuntimeDependencies) -> None:
        self.dependencies = dependencies
        self.manifest_digest = sha256_digest(dependencies.manifest)

    def _contract(self, operation_id: str) -> ContractSpecV2:
        try:
            return self.dependencies.manifest.contract(operation_id)
        except KeyError as exc:
            raise SecurityError("Identity operation is outside the signed manifest") from exc

    def _governance(
        self,
        contract: ContractSpecV2,
        *,
        refresh: bool = False,
    ) -> EffectiveOperationGovernance:
        verified = (
            self.dependencies.governance.refresh()
            if refresh
            else self.dependencies.governance
        )
        return resolve_operation_governance(
            verified.policy,
            contract,
            contract_manifest_digest=self.manifest_digest,
        )

    @staticmethod
    def _parameters(
        values: dict[str, str | bool | tuple[str, ...]],
    ) -> tuple[PlanParameter, ...]:
        return tuple(
            PlanParameter(name=name, value=value)
            for name, value in sorted(values.items())
        )

    def _plan_id(self, operation_id: str, idempotency_key: UUID) -> UUID:
        return uuid5(
            NAMESPACE_URL,
            (
                f"m365-secure-mcp:{self.dependencies.operator.deployment_namespace}:"
                f"{operation_id}:{idempotency_key}"
            ),
        )

    @staticmethod
    def _assert_existing_request(
        plan: OperatorPlan,
        *,
        governance: EffectiveOperationGovernance,
        intended_operator_id: UUID,
        target_user_id: UUID,
        parameters: tuple[PlanParameter, ...],
    ) -> None:
        plan.validate_governance(governance)
        if (
            plan.intended_operator_id != intended_operator_id
            or plan.target.object_id != target_user_id
            or plan.parameters != parameters
        ):
            raise SecurityError(
                "idempotency key is already bound to another exact plan"
            )

    async def _new_plan(
        self,
        *,
        contract: ContractSpecV2,
        governance: EffectiveOperationGovernance,
        provider: IdentityOperationProvider,
        plan_id: UUID,
        intended_operator_id: UUID,
        target_user_id: UUID,
        parameters: tuple[PlanParameter, ...],
        as_of: datetime,
    ) -> OperatorPlan:
        target = TargetReference(
            resource_type=ResourceFenceType.USER,
            object_id=target_user_id,
            opaque_reference=_opaque(
                "target",
                f"{governance.tenant_id}:{contract.id}:{target_user_id}",
            ),
        )
        compensation = CompensationDeclaration(
            classification=contract.compensation,
            manual_handoff_id=(
                "manual.identity_effect_review"
                if contract.compensation is CompensationClass.NOT_COMPENSATABLE
                else None
            ),
        )
        expected = ExpectedPostcondition(
            check_id="identity.expected_postcondition",
            expected_digest=sha256_digest(
                {
                    "operation_id": contract.id,
                    "target": str(target_user_id),
                    "parameters": [
                        item.model_dump(mode="json") for item in parameters
                    ],
                }
            ),
        )
        placeholder = (
            PreconditionBinding(
                check_id="identity.complete_protected_snapshot",
                evidence_digest="sha256:" + ("0" * 64),
            ),
        )
        provisional = self.dependencies.operator.build_effectful_plan(
            governance=governance,
            plan_id=plan_id,
            nonce=uuid5(NAMESPACE_URL, f"{plan_id}:nonce"),
            intended_operator_id=intended_operator_id,
            target=target,
            parameters=parameters,
            preconditions=placeholder,
            expected_postcondition=expected,
            compensation=compensation,
            observation_timeout_seconds=min(contract.plan_ttl_seconds, 300),
            maximum_observation_polls=10,
            created_at=as_of,
            not_before=as_of,
            expires_at=as_of + timedelta(seconds=contract.plan_ttl_seconds),
        )
        preconditions = await provider.preflight(provisional)
        return self.dependencies.operator.build_effectful_plan(
            governance=governance,
            plan_id=plan_id,
            nonce=uuid5(NAMESPACE_URL, f"{plan_id}:nonce"),
            intended_operator_id=intended_operator_id,
            target=target,
            parameters=parameters,
            preconditions=preconditions,
            expected_postcondition=expected,
            compensation=compensation,
            observation_timeout_seconds=min(contract.plan_ttl_seconds, 300),
            maximum_observation_polls=10,
            created_at=as_of,
            not_before=as_of,
            expires_at=as_of + timedelta(seconds=contract.plan_ttl_seconds),
        )

    def _private_evidence(
        self,
        *,
        plan: OperatorPlan,
        contract: ContractSpecV2,
        record: DurableOperationRecord,
        created_at: datetime,
    ) -> None:
        if record.status not in _TERMINAL_OR_EFFECT_STATES:
            return
        change_reference = f"change:{record.operation_id}"
        receipt_reference = f"receipt:{record.operation_id}"
        change_record = ChangeRecord(
            operation_id=record.operation_id,
            contract_id=contract.id,
            contract_digest=plan.contract_digest,
            policy_digest=plan.policy_digest,
            target_fingerprint=_opaque(
                "sha256",
                f"{plan.tenant_id}:{plan.target.object_id}",
            ),
            changed_fields=[item.name for item in plan.parameters],
            authorization_mode=plan.authorization_mode,
            authorization_basis=plan.authorization_mode.value,
            verification=plan.verification,
            compensation=plan.compensation.classification.value,
            recovery_capsule_reference=f"capsule:{record.operation_id}",
            created_at=created_at,
        )
        receipt = GovernedReceipt(
            operation_id=record.operation_id,
            contract_id=contract.id,
            status=_lifecycle_operation_status(record),
            contract_digest=plan.contract_digest,
            policy_digest=plan.policy_digest,
            authorization_basis=plan.authorization_mode.value,
            verification=plan.verification,
            change_record_reference=change_reference,
            evidence_reference=(
                record.evidence_reference
                or _opaque("evidence", str(record.operation_id))
            ),
            created_at=created_at,
        )
        self.dependencies.recovery.store_effectful_record(
            operation_id=record.operation_id,
            contract_id=contract.id,
            tenant_id=str(plan.tenant_id),
            record={
                "plan": plan.model_dump(mode="json"),
                "durable_state": record.model_dump(mode="json"),
                "change_record": change_record.model_dump(mode="json"),
                "receipt": receipt.model_dump(mode="json"),
                "public_references": {
                    "change_record": change_reference,
                    "receipt": receipt_reference,
                },
            },
        )

    async def invoke(
        self,
        *,
        operation_id: str,
        intended_operator_id: UUID,
        target_user_id: UUID,
        parameters: dict[str, str | bool | tuple[str, ...]],
        idempotency_key: UUID,
        as_of: datetime | None = None,
    ) -> IdentityOperationPublicResult:
        now = as_of or datetime.now(UTC)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Identity operation time must be timezone-aware")
        contract = self._contract(operation_id)
        governance = self._governance(contract)
        plan_parameters = self._parameters(parameters)
        provider = IdentityOperationProvider(
            backend=self.dependencies.backend,
            resources=self.dependencies.governance.policy.resources,
            operation_id=operation_id,
        )
        plan_id = self._plan_id(operation_id, idempotency_key)
        request = self.dependencies.approval_broker.load_request(plan_id)
        if request is None:
            plan = await self._new_plan(
                contract=contract,
                governance=governance,
                provider=provider,
                plan_id=plan_id,
                intended_operator_id=intended_operator_id,
                target_user_id=target_user_id,
                parameters=plan_parameters,
                as_of=now,
            )
            request = self.dependencies.approval_broker.prepare(
                plan,
                requested_at=now,
            )
        else:
            plan = request.plan
            self._assert_existing_request(
                plan,
                governance=governance,
                intended_operator_id=intended_operator_id,
                target_user_id=target_user_id,
                parameters=plan_parameters,
            )
        execution_id = uuid5(NAMESPACE_URL, f"{plan.plan_id}:execution")
        existing = self.dependencies.lifecycle.store.get(execution_id)
        if existing is not None and existing.status in {
            OperatorLifecycleStatus.EXECUTED_ACCEPTED,
            OperatorLifecycleStatus.OBSERVING,
        }:
            governance = self._governance(contract, refresh=True)
            plan.validate_governance(governance)
            record = await self.dependencies.lifecycle.observe(
                operation_id=execution_id,
                provider=provider,
                as_of=now,
            )
        else:
            authority_ids = tuple(
                item.authority_id for item in governance.approval_authorities
            )
            approvals = self.dependencies.approval_broker.approvals(
                plan,
                authority_ids=authority_ids,
            )
            if approvals:
                governance = self._governance(contract, refresh=True)
            record = await self.dependencies.operator.execute_effectful(
                plan=plan,
                governance=governance,
                approvals=approvals,
                validator=self.dependencies.approval_validator,
                lifecycle=self.dependencies.lifecycle,
                provider=provider,
                operation_id=execution_id,
                as_of=now,
            )
        self._private_evidence(
            plan=plan,
            contract=contract,
            record=record,
            created_at=now,
        )
        has_effect_evidence = record.status in _TERMINAL_OR_EFFECT_STATES
        progress = self.dependencies.lifecycle.public(record)
        return IdentityOperationPublicResult(
            status=_lifecycle_operation_status(record),
            operation_reference=progress.operation_reference,
            operator_action=progress.operator_action,
            safe_to_retry=progress.safe_to_retry,
            evidence_reference=progress.evidence_reference,
            observation_reference=progress.observation_reference,
            contract_id=contract.id,
            contract_digest=sha256_digest(contract),
            plan_digest=plan.digest,
            verification=contract.verification,
            approval_request_reference=f"approval-request:{plan.plan_id}",
            receipt_reference=(
                f"receipt:{record.operation_id}" if has_effect_evidence else None
            ),
            change_record_reference=(
                f"change:{record.operation_id}" if has_effect_evidence else None
            ),
        )


def build_identity_runtime(
    *,
    manifest: ContractManifestV2,
    governance: VerifiedGovernancePolicy,
    graph: GraphClient,
    operator: ChangeSafeOperator,
    approval_broker: ExternalOperatorApprovalBroker,
    replay_store: ApprovalReplayStore,
    lifecycle_store: DurableOperationStore,
    recovery: RecoveryCapsuleStore,
    backend: ClosedIdentityBackend | None = None,
) -> IdentityContractRuntime:
    if not isinstance(governance.policy, GovernancePolicyV3):
        raise SecurityError("Identity runtime requires Governance v3")
    for binding in governance.policy.operations.approval_authorities:
        authority = approval_broker.trust_registry.authority(
            binding.authority_id
        )
        if (
            authority.identity_id != binding.identity_id
            or authority.key_id != binding.key_id
            or authority.signer_group != binding.signer_group
            or authority.public_key_sha256 != binding.public_key_sha256
        ):
            raise SecurityError(
                "operator approval trust differs from signed Governance"
            )
    return IdentityContractRuntime(
        IdentityRuntimeDependencies(
            manifest=manifest,
            governance=governance,
            backend=backend or MicrosoftGraphIdentityBackend(graph),
            operator=operator,
            approval_broker=approval_broker,
            approval_validator=ApprovalSetValidator(
                trust_registry=approval_broker.trust_registry,
                replay_store=replay_store,
            ),
            lifecycle=DurableOperatorLifecycle(lifecycle_store),
            recovery=recovery,
        )
    )
