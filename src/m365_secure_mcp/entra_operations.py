"""Governed Entra operational-profile vertical slice."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from .change_safe import (
    ChangeSafeOperator,
    ChangeSafePlan,
    ExternalApprovalBroker,
    GovernedOperationError,
    GovernedWriteUncertainError,
)
from .config import Settings
from .contract_manifest import (
    AuthorizationMode,
    ContractSpec,
    load_global_manifest,
    sha256_digest,
)
from .governance import (
    AuthorizationDecision,
    GovernancePolicyError,
    VerifiedGovernancePolicy,
)
from .graph import GraphClient, GraphError
from .models import UpdateEntraUserOperationalProfileInput
from .operations import (
    OperationRecord,
    OperationStatus,
    PermissionImpactPreview,
    ResponsibleParty,
)
from .recovery import RecoveryCapsuleStore
from .security import (
    SecurityError,
    SecurityPolicy,
    WriteVerificationError,
    path_segment,
)

CONTRACT_ID = "entra.user.operational_profile.update"
PROFILE_FIELD_MAP = {
    "department": "department",
    "job_title": "jobTitle",
    "office_location": "officeLocation",
}
USER_SELECT = (
    "id,userType,onPremisesSyncEnabled,onPremisesLastSyncDateTime,"
    "onPremisesImmutableId,department,jobTitle,officeLocation"
)
EXCLUDED_CAPABILITIES = [
    "accountEnabled",
    "authenticationMethods",
    "businessPhones",
    "displayName",
    "identities",
    "licenseAssignments",
    "mail",
    "mobilePhone",
    "passwordProfile",
    "roles",
    "usageLocation",
    "userPrincipalName",
]


@dataclass(frozen=True)
class UserSnapshot:
    user_id: str
    user_type: str
    on_premises_sync_enabled: bool | None
    on_premises_last_sync: str | None
    on_premises_immutable_id: str | None
    profile: dict[str, str | None]

    @property
    def digest(self) -> str:
        return sha256_digest(
            {
                "user_id": self.user_id,
                "user_type": self.user_type,
                "on_premises_sync_enabled": self.on_premises_sync_enabled,
                "on_premises_last_sync": self.on_premises_last_sync,
                "on_premises_immutable_id": self.on_premises_immutable_id,
                "profile": self.profile,
            }
        )


OperationalProfilePlan = ChangeSafePlan[UserSnapshot]


class EntraOperationalProfileService:
    """Execute one fixed T1 contract; no endpoint or method is caller-controlled."""

    def __init__(
        self,
        *,
        settings: Settings,
        graph: GraphClient,
        runtime_policy: SecurityPolicy,
        governance: VerifiedGovernancePolicy,
        recovery: RecoveryCapsuleStore,
        approval_broker: ExternalApprovalBroker | None = None,
    ) -> None:
        self.settings = settings
        self.graph = graph
        self.runtime_policy = runtime_policy
        self.governance = governance
        self.recovery = recovery
        self.change_safe = ChangeSafeOperator(
            tenant_id=settings.tenant_id,
            deployment_namespace=settings.deployment_namespace,
            approval_broker=approval_broker,
        )

    @staticmethod
    def contract() -> ContractSpec:
        return load_global_manifest().contract(CONTRACT_ID)

    def _permission_impact(
        self,
        contract: ContractSpec,
        changed_fields: list[str],
    ) -> PermissionImpactPreview:
        return self.change_safe.permission_impact(
            contract,
            changed_fields=changed_fields,
            excludes=EXCLUDED_CAPABILITIES,
        )

    def _policy_authorization_context(
        self,
        contract: ContractSpec,
    ) -> AuthorizationDecision:
        policy = self.governance.policy
        mode = policy.authorization_overrides.get(
            contract.id,
            contract.authorization_mode,
        )
        basis_by_mode: dict[
            AuthorizationMode,
            Literal[
                "standing_policy",
                "explicit_plan",
                "dual_control",
                "break_glass",
                "prohibited",
            ],
        ] = {
            AuthorizationMode.STANDING_POLICY: "standing_policy",
            AuthorizationMode.EXPLICIT_PLAN: "explicit_plan",
            AuthorizationMode.DUAL_CONTROL: "dual_control",
            AuthorizationMode.BREAK_GLASS_ONLY: "break_glass",
            AuthorizationMode.PROHIBITED: "prohibited",
        }
        basis = basis_by_mode.get(mode, "standing_policy")
        return AuthorizationDecision(
            mode=mode,
            basis=basis,
            profile=policy.active_profile,
            policy_digest=self.governance.policy_digest,
        )

    def _preflight_failure_record(
        self,
        *,
        operation_id: UUID,
        contract: ContractSpec,
        params: UpdateEntraUserOperationalProfileInput,
        status: OperationStatus,
        reason_code: str,
        operator_action: str,
        responsible_party: ResponsibleParty,
        policy_change_required: bool,
        contract_change_required: bool = False,
    ) -> OperationRecord:
        authorization = self._policy_authorization_context(contract)
        return OperationRecord(
            status=status,
            reason_code=reason_code,
            operator_action=operator_action,
            responsible_party=responsible_party,
            authorization_mode=authorization.mode,
            authorization_basis=authorization.basis,
            required_profile=authorization.profile.value,
            policy_change_required=policy_change_required,
            contract_change_required=contract_change_required,
            new_plan_required=True,
            safe_to_retry=False,
            evidence_reference=f"operation:{operation_id}",
            permission_impact=self._permission_impact(
                contract,
                sorted(self._requested(params)),
            ),
        )

    @staticmethod
    def _requested(
        params: UpdateEntraUserOperationalProfileInput,
    ) -> dict[str, str]:
        requested: dict[str, str] = {}
        for input_name, graph_name in PROFILE_FIELD_MAP.items():
            if input_name not in params.model_fields_set:
                continue
            value = getattr(params, input_name)
            if not isinstance(value, str):
                raise ValueError("operational profile values must be strings")
            requested[graph_name] = value
        return requested

    def _target_fingerprint(self, user_id: str) -> str:
        digest = hashlib.sha256(
            f"{self.settings.deployment_namespace}:{user_id}".encode()
        ).hexdigest()
        return f"sha256:{digest}"

    async def _read_user(self, user_id: str) -> UserSnapshot:
        endpoint = f"/users/{path_segment(user_id)}"
        data = await self.graph.request_json(
            "GET",
            endpoint,
            params={"$select": USER_SELECT},
        )
        if str(data.get("id", "")).lower() != user_id.lower():
            raise SecurityError("Graph returned a different Entra user")
        user_type = str(data.get("userType", ""))
        sync_value = data.get("onPremisesSyncEnabled")
        if sync_value not in {True, False, None}:
            raise SecurityError("Graph returned an invalid source-of-authority state")
        profile: dict[str, str | None] = {}
        for field in ("department", "jobTitle", "officeLocation"):
            value = data.get(field)
            if value is not None and not isinstance(value, str):
                raise SecurityError("Graph returned an invalid operational profile")
            profile[field] = value
        snapshot = UserSnapshot(
            user_id=user_id,
            user_type=user_type,
            on_premises_sync_enabled=sync_value,
            on_premises_last_sync=(
                str(data["onPremisesLastSyncDateTime"])
                if data.get("onPremisesLastSyncDateTime")
                else None
            ),
            on_premises_immutable_id=(
                str(data["onPremisesImmutableId"])
                if data.get("onPremisesImmutableId")
                else None
            ),
            profile=profile,
        )
        self._enforce_user_fences(snapshot)
        return snapshot

    @staticmethod
    def _enforce_user_fences(snapshot: UserSnapshot) -> None:
        if snapshot.user_type != "Member":
            raise SecurityError("operational profile writes require a Member user")
        if (
            snapshot.on_premises_sync_enabled is True
            or snapshot.on_premises_last_sync is not None
            or snapshot.on_premises_immutable_id is not None
        ):
            raise SecurityError(
                "operational profile writes require a never-synced cloud-managed user"
            )

    async def _ensure_non_privileged(self, user_id: str) -> None:
        role_params: dict[str, str | int] = {
            "$filter": f"principalId eq '{user_id}'",
            "$select": "id,principalId",
            "$top": 1,
        }
        checks: tuple[
            tuple[str, dict[str, str | int], dict[str, str] | None],
            ...,
        ] = (
            (
                "/roleManagement/directory/roleAssignments",
                role_params,
                None,
            ),
            (
                "/roleManagement/directory/roleAssignmentScheduleInstances",
                role_params,
                None,
            ),
            (
                "/roleManagement/directory/roleEligibilityScheduleInstances",
                role_params,
                None,
            ),
            (
                (
                    f"/users/{path_segment(user_id)}/"
                    "transitiveMemberOf/microsoft.graph.group"
                ),
                {
                    "$count": "true",
                    "$filter": "isAssignableToRole eq true",
                    "$select": "id",
                    "$top": 1,
                },
                {"ConsistencyLevel": "eventual"},
            ),
        )
        for endpoint, params, headers in checks:
            data = await self.graph.request_json(
                "GET",
                endpoint,
                params=params,
                headers=headers,
            )
            values = data.get("value")
            if not isinstance(values, list):
                raise SecurityError(
                    "Graph returned an invalid privileged-role preflight result"
                )
            if values:
                raise SecurityError(
                    "target user has an active, eligible, or group-derived directory role"
                )

    def _base_record(
        self,
        *,
        status: OperationStatus,
        reason_code: str,
        operator_action: str,
        responsible_party: ResponsibleParty,
        authorization: AuthorizationDecision,
        plan: OperationalProfilePlan,
        safe_to_retry: bool,
        new_plan_required: bool,
        evidence_reference: str,
    ) -> OperationRecord:
        if authorization != plan.authorization:
            raise SecurityError("operation record authorization changed unexpectedly")
        return self.change_safe.base_record(
            status=status,
            reason_code=reason_code,
            operator_action=operator_action,
            responsible_party=responsible_party,
            plan=plan,
            evidence_reference=evidence_reference,
            safe_to_retry=safe_to_retry,
            new_plan_required=new_plan_required,
        )

    async def preflight(
        self,
        params: UpdateEntraUserOperationalProfileInput,
    ) -> OperationalProfilePlan:
        contract = self.contract()
        if self.governance.policy.contract_manifest_digest != sha256_digest(
            load_global_manifest()
        ):
            raise GovernancePolicyError(
                "governance policy is bound to a different contract manifest",
                reason_code="CONTRACT_VERSION_MISMATCH",
            )
        try:
            self.runtime_policy.require_write_action(CONTRACT_ID)
        except SecurityError as exc:
            raise GovernancePolicyError(
                str(exc),
                reason_code="DENIED_OUT_OF_CONTRACT",
            ) from exc
        try:
            user_id = self.runtime_policy.authorize_target_user(
                str(params.user_id)
            )
        except SecurityError as exc:
            raise GovernancePolicyError(
                str(exc),
                reason_code="RESOURCE_FENCE_MISMATCH",
            ) from exc
        authorization = self.governance.authorize(
            contract,
            tenant_id=self.settings.tenant_id,
            target_user_id=user_id,
            local_target_user_ids=self.settings.target_user_ids,
        )
        principal = await self.graph.ensure_principal()
        requested = self._requested(params)
        changed_fields = sorted(requested)
        permission_impact = self._permission_impact(contract, changed_fields)
        snapshot = await self._read_user(user_id)
        await self._ensure_non_privileged(user_id)
        effective_changes = [
            field
            for field, value in requested.items()
            if snapshot.profile.get(field) != value
        ]
        if not effective_changes:
            raise SecurityError("requested operational profile already matches Graph")
        now = datetime.now(UTC)
        return self.change_safe.build_plan(
            contract=contract,
            authorization=authorization,
            operator_id=principal.object_id,
            idempotency_key=params.idempotency_key,
            snapshot=snapshot,
            precondition_digest=snapshot.digest,
            requested=requested,
            normalized_parameters=params.model_dump(mode="json"),
            target_fingerprint=self._target_fingerprint(user_id),
            changed_fields=sorted(effective_changes),
            permission_impact=permission_impact,
            now=now,
        )

    async def preview(
        self,
        params: UpdateEntraUserOperationalProfileInput,
        *,
        operation_id: UUID,
    ) -> OperationRecord:
        """Run the complete non-write plan path without simulating Graph effect."""

        plan = await self.preflight(params)
        record = self.change_safe.base_record(
            status=OperationStatus.CANCELLED_BEFORE_EFFECT,
            reason_code="PREFLIGHT_COMPLETE_NO_EFFECT",
            operator_action=(
                "Review the impact preview. No write was attempted; execute the "
                "same contracted operation only while its preconditions remain fresh."
            ),
            responsible_party=ResponsibleParty.OPERATOR,
            plan=plan,
            evidence_reference=f"operation:{operation_id}",
            safe_to_retry=True,
            new_plan_required=False,
        )
        return record.model_copy(
            update={
                "details": {
                    **record.details,
                    "preflight_only": True,
                    "graph_write_attempted": False,
                    "graph_simulation_claimed": False,
                }
            }
        )

    async def execute(
        self,
        params: UpdateEntraUserOperationalProfileInput,
        *,
        operation_id: UUID,
    ) -> OperationRecord:
        contract = self.contract()
        try:
            plan = await self.preflight(params)
        except GovernancePolicyError as exc:
            reason_code = exc.reason_code
            out_of_contract = reason_code == "DENIED_OUT_OF_CONTRACT"
            record = self._preflight_failure_record(
                operation_id=operation_id,
                contract=contract,
                params=params,
                status=(
                    OperationStatus.DENIED_OUT_OF_CONTRACT
                    if out_of_contract
                    else OperationStatus.DENIED_BY_POLICY
                ),
                reason_code=reason_code,
                operator_action=(
                    "Select a signed profile that enables this contract."
                    if out_of_contract
                    else (
                        "Have the governance owner correct and re-sign the tenant "
                        "policy; runtime cannot weaken it."
                    )
                ),
                responsible_party=ResponsibleParty.GOVERNANCE_OWNER,
                policy_change_required=True,
            )
            raise GovernedOperationError(str(exc), record) from exc
        except SecurityError as exc:
            record = self._preflight_failure_record(
                operation_id=operation_id,
                contract=contract,
                params=params,
                status=OperationStatus.BLOCKED_PRECONDITION,
                reason_code="TARGET_PRECONDITION_FAILED",
                operator_action=(
                    "Use a cloud-managed, non-privileged Member user whose current "
                    "profile differs from the requested values."
                ),
                responsible_party=ResponsibleParty.OPERATOR,
                policy_change_required=False,
            )
            raise GovernedOperationError(str(exc), record) from exc
        evidence_reference = f"operation:{operation_id}"
        approval = self.change_safe.authorization_gate(
            plan,
            evidence_reference=evidence_reference,
        )
        self.change_safe.ensure_fresh(
            plan,
            evidence_reference=evidence_reference,
        )

        # TOCTOU revalidation: the signed policy, contract digest, local fence,
        # user source of authority, role status, and current profile are all
        # checked again immediately before PATCH.
        refreshed_governance = self.governance.refresh()
        refreshed_contract = load_global_manifest().contract(CONTRACT_ID)
        if sha256_digest(refreshed_contract) != plan.contract_digest:
            raise GovernedOperationError(
                "contract changed after preflight",
                self._base_record(
                    status=OperationStatus.PLAN_EXPIRED,
                    reason_code="CONTRACT_VERSION_MISMATCH",
                    operator_action="Regenerate the plan against the current contract.",
                    responsible_party=ResponsibleParty.PRODUCT_MAINTAINER,
                    authorization=plan.authorization,
                    plan=plan,
                    safe_to_retry=False,
                    new_plan_required=True,
                    evidence_reference=evidence_reference,
                ),
            )
        refreshed_governance.authorize(
            refreshed_contract,
            tenant_id=self.settings.tenant_id,
            target_user_id=str(params.user_id),
            local_target_user_ids=self.settings.target_user_ids,
        )
        self.runtime_policy.authorize_target_user(str(params.user_id))
        current = await self._read_user(str(params.user_id))
        await self._ensure_non_privileged(str(params.user_id))
        if current.digest != plan.snapshot.digest:
            record = self._base_record(
                status=OperationStatus.PLAN_EXPIRED,
                reason_code="FRESH_PRECONDITION_MISMATCH",
                operator_action="Regenerate the plan from the current user state.",
                responsible_party=ResponsibleParty.OPERATOR,
                authorization=plan.authorization,
                plan=plan,
                safe_to_retry=True,
                new_plan_required=True,
                evidence_reference=evidence_reference,
            )
            raise GovernedOperationError("user changed after preflight", record)

        capsule_reference = self.recovery.store(
            operation_id=operation_id,
            contract_id=CONTRACT_ID,
            tenant_id=self.settings.tenant_id,
            target_user_id=str(params.user_id),
            previous_profile=plan.snapshot.profile,
            requested_profile=plan.requested,
        )
        # Approval is consumed only after every TOCTOU check and recovery
        # precondition passes, but before the first effectful Graph call.
        try:
            self.change_safe.consume_approval(approval)
        except SecurityError as exc:
            raise GovernedOperationError(
                str(exc),
                self._base_record(
                    status=OperationStatus.BLOCKED_PRECONDITION,
                    reason_code="EXTERNAL_APPROVAL_REPLAY_REJECTED",
                    operator_action=(
                        "Do not reuse this approval. Generate a new plan and "
                        "obtain a new external signature."
                    ),
                    responsible_party=ResponsibleParty.OPERATOR,
                    authorization=plan.authorization,
                    plan=plan,
                    safe_to_retry=False,
                    new_plan_required=True,
                    evidence_reference=evidence_reference,
                ),
            ) from exc
        endpoint = f"/users/{path_segment(str(params.user_id))}"
        try:
            await self.graph.request_json(
                "PATCH",
                endpoint,
                json_body=plan.requested,
            )
        except GraphError as exc:
            if exc.write_may_have_committed:
                uncertain = self.change_safe.uncertain_record(
                    plan=plan,
                    evidence_reference=evidence_reference,
                    reason_code="GRAPH_WRITE_OUTCOME_UNCERTAIN",
                    operator_action=(
                        "Perform a read-only verification; do not retry the write."
                    ),
                )
                raise GovernedWriteUncertainError(str(exc), uncertain) from exc
            exc.operation_record = self._base_record(  # type: ignore[attr-defined]
                status=OperationStatus.BLOCKED_PRECONDITION,
                reason_code="GRAPH_REJECTED_BEFORE_EFFECT",
                operator_action="Correct the documented Graph precondition and replan.",
                responsible_party=ResponsibleParty.TENANT_ADMIN,
                authorization=plan.authorization,
                plan=plan,
                safe_to_retry=False,
                new_plan_required=True,
                evidence_reference=evidence_reference,
            )
            raise

        try:
            observed = await self._read_user(str(params.user_id))
            for field, expected in plan.requested.items():
                if observed.profile.get(field) != expected:
                    raise WriteVerificationError(
                        f"post-read did not confirm requested field '{field}'"
                    )
        except Exception as exc:
            uncertain = self.change_safe.uncertain_record(
                plan=plan,
                evidence_reference=evidence_reference,
                reason_code="POST_READ_VERIFICATION_FAILED",
                operator_action=(
                    "Inspect the user with a read-only contract; do not repeat the write."
                ),
            )
            raise GovernedWriteUncertainError(str(exc), uncertain) from exc

        return self.change_safe.verified_record(
            operation_id=operation_id,
            plan=plan,
            contract=refreshed_contract,
            evidence_reference=evidence_reference,
            target_fingerprint=self._target_fingerprint(str(params.user_id)),
            capsule_reference=capsule_reference,
        )


def render_operation(record: OperationRecord) -> str:
    """Render only the deterministic, value-minimized operation schema."""

    return json.dumps(
        record.model_dump(mode="json", exclude_none=True),
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    )
