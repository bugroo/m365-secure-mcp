"""Reviewed, disabled-by-default runner for one exact Core Identity lab case."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from .auth import TokenProvider
from .change_safe import ChangeSafeOperator
from .config import Profile, Settings
from .contract_compiler import load_identity_candidate
from .contract_manifest import sha256_digest
from .governance import (
    GovernancePolicyV3,
    load_verified_governance_policy,
)
from .graph import GraphClient, GraphError
from .identity_live_lab import (
    REQUIRED_DELEGATED_SCOPES,
    IdentityLiveLabInventory,
    LiveLabLevel,
    LiveLabOperatorProfileName,
    PublicLiveLabCase,
    validate_live_lab_gate,
)
from .identity_operations import MicrosoftGraphIdentityBackend
from .identity_runtime import build_identity_runtime
from .operations import OperationStatus
from .operator_authority import (
    ApprovalReplayStore,
    ExternalOperatorApprovalBroker,
)
from .operator_lifecycle import DurableOperationStore
from .recovery import RecoveryCapsuleStore
from .security import SecurityError, SecurityPolicy

ROLE_TEMPLATE_IDS = {
    "Global Reader": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "Groups Administrator": "fdd7a751-b60b-444a-984c-02652afe8b1",
    "License Administrator": "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
}

_EXPECTED_PREFLIGHT_REJECTION = {
    "allowlist.outside_resource_rejected": "outside the signed user allowlist",
    "license.capacity_rejected": "license preconditions failed closed",
    "license.service_plan_rejected": "non-allowlisted service plan",
    "license.usage_location_rejected": "license preconditions failed closed",
    "protected_object.rejected": "Identity target is protected",
}


@dataclass(frozen=True)
class CoreScenario:
    operator_profile: LiveLabOperatorProfileName
    operation_id: Literal[
        "entra.user.sessions.revoke",
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
        "entra.user.direct_license.set",
    ]
    resource_type: Literal[
        "user",
        "group",
        "license",
        "relationship",
        "session",
    ]
    target_field: str
    parameters: dict[str, object]
    expected_status: str


@dataclass(frozen=True)
class CoreNegativeScenario:
    operator_profile: LiveLabOperatorProfileName
    operation_id: Literal[
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
    ]
    resource_type: Literal["user", "relationship"]
    check: Literal[
        "cross_tenant",
        "effect_role_missing",
        "evidence_role_missing",
        "profile_isolation",
    ]
    expected_role_names: tuple[str, ...]
    error_code: str


class CoreCaseInvocation(BaseModel):
    """Private operator result; only ``evidence`` may enter public artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: OperationStatus
    operator_action: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    approval_request_reference: str | None = Field(
        default=None,
        pattern=r"^approval-request:[0-9a-f-]{36}$",
    )
    plan_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    evidence: PublicLiveLabCase | None = None


class _AmbiguousAfterAcceptedRevokeBackend(MicrosoftGraphIdentityBackend):
    """Closed lab fault: lose transport certainty after Graph accepted revoke."""

    async def revoke_sessions(self, user_id: UUID) -> bool:
        accepted = await super().revoke_sessions(user_id)
        if not accepted:
            return False
        raise GraphError(
            "live-lab transport certainty intentionally removed after acceptance",
            write_may_have_committed=True,
        )


def _scenario(
    inventory: IdentityLiveLabInventory,
    scenario: str,
) -> CoreScenario:
    scenarios = {
        "account.disable": CoreScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "normal_enabled_user_id",
            {"account_enabled": False},
            "EXECUTED_VERIFIED",
        ),
        "account.enable": CoreScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "normal_disabled_user_id",
            {"account_enabled": True},
            "EXECUTED_VERIFIED",
        ),
        "account.noop": CoreScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "normal_enabled_user_id",
            {"account_enabled": True},
            "EXECUTED_VERIFIED",
        ),
        "account.toctou_rejected": CoreScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "normal_enabled_user_id",
            {"account_enabled": False},
            "BLOCKED_PRECONDITION",
        ),
        "allowlist.outside_resource_rejected": CoreScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "outside_allowlist_user_id",
            {"account_enabled": False},
            "BLOCKED_PRECONDITION",
        ),
        "license.assign_direct": CoreScenario(
            LiveLabOperatorProfileName.LICENSE,
            "entra.user.direct_license.set",
            "license",
            "normal_enabled_user_id",
            {"license_assigned": True},
            "EXECUTED_VERIFIED",
        ),
        "license.capacity_rejected": CoreScenario(
            LiveLabOperatorProfileName.LICENSE,
            "entra.user.direct_license.set",
            "license",
            "normal_enabled_user_id",
            {"license_assigned": True},
            "BLOCKED_PRECONDITION",
        ),
        "license.noop": CoreScenario(
            LiveLabOperatorProfileName.LICENSE,
            "entra.user.direct_license.set",
            "license",
            "direct_license_user_id",
            {"license_assigned": True},
            "EXECUTED_VERIFIED",
        ),
        "license.remove_direct": CoreScenario(
            LiveLabOperatorProfileName.LICENSE,
            "entra.user.direct_license.set",
            "license",
            "direct_license_user_id",
            {"license_assigned": False},
            "EXECUTED_VERIFIED",
        ),
        "license.service_plan_rejected": CoreScenario(
            LiveLabOperatorProfileName.LICENSE,
            "entra.user.direct_license.set",
            "license",
            "normal_enabled_user_id",
            {"license_assigned": True, "disallowed_plan": True},
            "BLOCKED_PRECONDITION",
        ),
        "license.usage_location_rejected": CoreScenario(
            LiveLabOperatorProfileName.LICENSE,
            "entra.user.direct_license.set",
            "license",
            "no_usage_location_user_id",
            {"license_assigned": True},
            "BLOCKED_PRECONDITION",
        ),
        "membership.add": CoreScenario(
            LiveLabOperatorProfileName.GROUP,
            "entra.group.user_membership.add",
            "relationship",
            "non_member_user_id",
            {},
            "EXECUTED_VERIFIED",
        ),
        "membership.add_noop": CoreScenario(
            LiveLabOperatorProfileName.GROUP,
            "entra.group.user_membership.add",
            "relationship",
            "already_member_user_id",
            {},
            "EXECUTED_VERIFIED",
        ),
        "membership.remove": CoreScenario(
            LiveLabOperatorProfileName.GROUP,
            "entra.group.user_membership.remove",
            "relationship",
            "already_member_user_id",
            {},
            "EXECUTED_VERIFIED",
        ),
        "membership.remove_noop": CoreScenario(
            LiveLabOperatorProfileName.GROUP,
            "entra.group.user_membership.remove",
            "relationship",
            "non_member_user_id",
            {},
            "EXECUTED_VERIFIED",
        ),
        "protected_object.rejected": CoreScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "administrator_user_id",
            {"account_enabled": False},
            "BLOCKED_PRECONDITION",
        ),
        "session.accepted_not_verified": CoreScenario(
            LiveLabOperatorProfileName.SESSION,
            "entra.user.sessions.revoke",
            "session",
            "normal_enabled_user_id",
            {},
            "EXECUTED_ACCEPTED",
        ),
        "session.uncertain_no_retry": CoreScenario(
            LiveLabOperatorProfileName.SESSION,
            "entra.user.sessions.revoke",
            "session",
            "normal_enabled_user_id",
            {},
            "EXECUTED_UNCERTAIN",
        ),
    }
    try:
        return scenarios[scenario]
    except KeyError as exc:
        raise SecurityError(
            "scenario requires the dedicated gate/fault harness, not a Graph write"
        ) from exc


def _negative_scenario(scenario: str) -> CoreNegativeScenario | None:
    return {
        "allowlist.cross_tenant_rejected": CoreNegativeScenario(
            LiveLabOperatorProfileName.NEGATIVE,
            "entra.user.account_state.set",
            "user",
            "cross_tenant",
            ("Global Reader",),
            "CROSS_TENANT_BINDING_REJECTED",
        ),
        "operator.effect_role_missing": CoreNegativeScenario(
            LiveLabOperatorProfileName.NEGATIVE,
            "entra.user.account_state.set",
            "user",
            "effect_role_missing",
            ("Global Reader",),
            "EFFECT_ROLE_MISSING_REJECTED",
        ),
        "operator.evidence_role_missing": CoreNegativeScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.user.account_state.set",
            "user",
            "evidence_role_missing",
            ("User Administrator",),
            "EVIDENCE_ROLE_MISSING_REJECTED",
        ),
        "operator.profile_isolation": CoreNegativeScenario(
            LiveLabOperatorProfileName.ACCOUNT,
            "entra.group.user_membership.add",
            "relationship",
            "profile_isolation",
            ("Global Reader", "User Administrator"),
            "OPERATOR_PROFILE_ISOLATION_REJECTED",
        ),
    }.get(scenario)


def _target(inventory: IdentityLiveLabInventory, spec: CoreScenario) -> UUID:
    if spec.resource_type == "relationship":
        return cast(UUID, getattr(inventory.core_relationships, spec.target_field))
    return cast(UUID, getattr(inventory.core_users, spec.target_field))


def _parameters(
    inventory: IdentityLiveLabInventory,
    spec: CoreScenario,
    target: UUID,
) -> dict[str, str | bool | tuple[str, ...]]:
    parameters: dict[str, str | bool | tuple[str, ...]] = {
        "user_id": str(target)
    }
    parameters.update(
        {
            key: value
            for key, value in spec.parameters.items()
            if isinstance(value, bool) and key != "disallowed_plan"
        }
    )
    if spec.operation_id.startswith("entra.group."):
        group_id = (
            inventory.core_relationships.already_member_group_id
            if "already_member" in spec.target_field
            else inventory.core_relationships.non_member_group_id
        )
        parameters["group_id"] = str(group_id)
    if spec.operation_id == "entra.user.direct_license.set":
        parameters["sku_id"] = str(inventory.licenses.allowed_sku_id)
        disabled = (
            (str(inventory.licenses.disallowed_service_plan_id),)
            if spec.parameters.get("disallowed_plan")
            else tuple(
                str(item)
                for item in inventory.licenses.allowed_service_plan_ids
            )
        )
        parameters["disabled_service_plan_ids"] = disabled
    return parameters


def _duration_bucket(
    seconds: float,
) -> Literal["under_1s", "1_to_5s", "5_to_30s", "30_to_120s", "over_120s"]:
    if seconds < 1:
        return "under_1s"
    if seconds < 5:
        return "1_to_5s"
    if seconds < 30:
        return "5_to_30s"
    if seconds < 120:
        return "30_to_120s"
    return "over_120s"


def _classification(
    status: OperationStatus,
) -> Literal["accepted", "verified", "uncertain", "blocked", "failed_confirmed"]:
    if status is OperationStatus.EXECUTED_ACCEPTED:
        return "accepted"
    if status is OperationStatus.EXECUTED_VERIFIED:
        return "verified"
    if status in {
        OperationStatus.EXECUTED_UNCERTAIN,
        OperationStatus.PLAN_EXPIRED,
    }:
        return "uncertain"
    if status is OperationStatus.FAILED_RETRYABLE:
        return "failed_confirmed"
    return "blocked"


async def _token_facts(
    *,
    settings: Settings,
    inventory: IdentityLiveLabInventory,
    operator_profile: LiveLabOperatorProfileName,
    expected_role_names: tuple[str, ...],
) -> GraphClient:
    expected_scopes = tuple(
        sorted(set(REQUIRED_DELEGATED_SCOPES) | {"User.Read"})
    )
    tokens = TokenProvider(settings, scopes=expected_scopes)
    actual_scopes = await tokens.get_delegated_scope_claims()
    if actual_scopes != set(expected_scopes):
        raise SecurityError("live token scope closure differs from the candidate")
    actual_role_ids = await tokens.get_directory_role_template_claims()
    expected_role_ids = {
        ROLE_TEMPLATE_IDS[role].lower() for role in expected_role_names
    }
    if actual_role_ids != expected_role_ids:
        raise SecurityError("live token role closure differs from the test case")
    graph = GraphClient(settings, tokens, SecurityPolicy(settings))
    principal = await graph.ensure_principal()
    if UUID(principal.object_id) != inventory.operators.get(
        operator_profile
    ).subject_id:
        await graph.close()
        raise SecurityError("live token subject differs from the operator profile")
    return graph


async def _run_negative_case(
    *,
    root: Path,
    inventory: IdentityLiveLabInventory,
    environ: dict[str, str],
    scenario: str,
    spec: CoreNegativeScenario,
    settings: Settings,
    started: float,
) -> CoreCaseInvocation:
    selected = LiveLabOperatorProfileName(environ["M365_LAB_OPERATOR_PROFILE"])
    if selected is not spec.operator_profile:
        raise SecurityError("selected operator profile cannot execute this test case")
    candidate = load_identity_candidate(root)
    contract_digest = sha256_digest(candidate.contract(spec.operation_id))
    graph: GraphClient | None = None
    try:
        if spec.check == "cross_tenant":
            altered = dict(environ)
            altered_tenant = uuid5(
                NAMESPACE_URL,
                f"m365-secure-mcp:cross-tenant-negative:{inventory.tenant_id}",
            )
            altered["M365_LAB_TENANT_ID"] = str(altered_tenant)
            try:
                validate_live_lab_gate(inventory, root=root, environ=altered)
            except SecurityError:
                pass
            else:
                raise SecurityError("cross-tenant lab binding was not rejected")
        else:
            graph = await _token_facts(
                settings=settings,
                inventory=inventory,
                operator_profile=spec.operator_profile,
                expected_role_names=spec.expected_role_names,
            )
            operator = inventory.operators.get(spec.operator_profile)
            if spec.check == "effect_role_missing":
                if operator.allowed_operation_ids:
                    raise SecurityError(
                        "negative operator unexpectedly enables an operation"
                    )
            elif spec.check == "evidence_role_missing":
                if "Global Reader" in spec.expected_role_names:
                    raise SecurityError(
                        "evidence-role negative case still has the evidence role"
                    )
            elif spec.check == "profile_isolation":
                if spec.operation_id in operator.allowed_operation_ids:
                    raise SecurityError(
                        "operator profile unexpectedly enables another operation"
                    )
    finally:
        if graph is not None:
            await graph.close()
    evidence = PublicLiveLabCase(
        lab_level=LiveLabLevel.CORE,
        scenario=scenario,
        resource_type=spec.resource_type,
        operation_id=spec.operation_id,
        expected_status=OperationStatus.BLOCKED_PRECONDITION.value,
        observed_status=OperationStatus.BLOCKED_PRECONDITION.value,
        approximate_duration=_duration_bucket(time.monotonic() - started),
        classification="blocked",
        error_code=spec.error_code,
        contract_digest=contract_digest,
        execution_state="passed",
    )
    return CoreCaseInvocation(
        status=OperationStatus.BLOCKED_PRECONDITION,
        operator_action="operator.retain_sanitized_negative_evidence",
        evidence=evidence,
    )


async def run_core_case(
    *,
    root: Path,
    inventory: IdentityLiveLabInventory,
    environ: dict[str, str],
    scenario: str,
    idempotency_key: UUID,
) -> CoreCaseInvocation:
    """Run or resume one reviewed scenario through the common operator path."""

    gate = validate_live_lab_gate(inventory, root=root, environ=environ)
    started = time.monotonic()
    negative = _negative_scenario(scenario)
    if negative is not None:
        operator = inventory.operators.get(negative.operator_profile)
        raw_auth_flow = environ.get("M365_AUTH_FLOW", "interactive")
        if raw_auth_flow not in {"interactive", "device_code"}:
            raise SecurityError("identity live-lab auth flow is invalid")
        settings = Settings(
            tenant_id=str(inventory.tenant_id),
            client_id=str(inventory.client_id),
            profile=Profile.READ,
            modules="profile",
            write_enabled=False,
            write_actions="",
            identity_operations_enabled=False,
            allowed_user_object_ids=str(operator.subject_id),
            token_cache_mode="keyring",  # noqa: S106
            keyring_service=operator.keyring_service,
            auth_flow=cast(
                Literal["interactive", "device_code"],
                raw_auth_flow,
            ),
            allow_device_code=(
                environ.get("M365_ALLOW_DEVICE_CODE", "").lower() == "true"
            ),
            operator_approval_dir=None,
            operator_approval_trust_path=None,
        )
        return await _run_negative_case(
            root=root,
            inventory=inventory,
            environ=environ,
            scenario=scenario,
            spec=negative,
            settings=settings,
            started=started,
        )
    settings = Settings.model_validate({})
    spec = _scenario(inventory, scenario)
    if gate.operator_profile is not spec.operator_profile:
        raise SecurityError("selected operator profile cannot execute this scenario")
    verified = load_verified_governance_policy(
        Path(environ["M365_GOVERNANCE_POLICY_PATH"]),
        Path(environ["M365_GOVERNANCE_PUBLIC_KEY_PATH"]),
    )
    if not isinstance(verified.policy, GovernancePolicyV3):
        raise SecurityError("Core effect scenario requires Governance v3")
    candidate = load_identity_candidate(root)
    operator = inventory.operators.get(spec.operator_profile)
    graph = await _token_facts(
        settings=settings,
        inventory=inventory,
        operator_profile=spec.operator_profile,
        expected_role_names=operator.required_roles,
    )
    try:
        broker = ExternalOperatorApprovalBroker(
            directory=Path(environ["M365_OPERATOR_APPROVAL_DIR"]),
            trust_registry_path=Path(
                environ["M365_OPERATOR_APPROVAL_TRUST_PATH"]
            ),
        )
        runtime = build_identity_runtime(
            manifest=candidate,
            governance=verified,
            graph=graph,
            operator=ChangeSafeOperator(
                tenant_id=str(inventory.tenant_id),
                deployment_namespace=settings.deployment_namespace,
            ),
            approval_broker=broker,
            replay_store=ApprovalReplayStore(
                settings.effective_operator_replay_db_path,
                settings.deployment_namespace,
            ),
            lifecycle_store=DurableOperationStore(
                settings.effective_operator_lifecycle_db_path,
                settings.deployment_namespace,
            ),
            recovery=RecoveryCapsuleStore(settings),
            backend=(
                _AmbiguousAfterAcceptedRevokeBackend(graph)
                if scenario == "session.uncertain_no_retry"
                else None
            ),
        )
        target = _target(inventory, spec)
        try:
            result = await runtime.invoke(
                operation_id=spec.operation_id,
                intended_operator_id=operator.subject_id,
                target_user_id=target,
                parameters=_parameters(inventory, spec, target),
                idempotency_key=idempotency_key,
            )
        except SecurityError as exc:
            expected_rejection = _EXPECTED_PREFLIGHT_REJECTION.get(scenario)
            if expected_rejection is None or expected_rejection not in str(exc):
                raise
            evidence = PublicLiveLabCase(
                lab_level=LiveLabLevel.CORE,
                scenario=scenario,
                resource_type=spec.resource_type,
                operation_id=spec.operation_id,
                expected_status=OperationStatus.BLOCKED_PRECONDITION.value,
                observed_status=OperationStatus.BLOCKED_PRECONDITION.value,
                approximate_duration=_duration_bucket(
                    time.monotonic() - started
                ),
                classification="blocked",
                error_code="PREFLIGHT_FAIL_CLOSED",
                contract_digest=sha256_digest(
                    candidate.contract(spec.operation_id)
                ),
                execution_state="passed",
            )
            return CoreCaseInvocation(
                status=OperationStatus.BLOCKED_PRECONDITION,
                operator_action="operator.retain_sanitized_negative_evidence",
                evidence=evidence,
            )
    finally:
        await graph.close()
    status = result.status
    if status is OperationStatus.AWAITING_APPROVAL:
        return CoreCaseInvocation(
            status=status,
            operator_action="approver.review_exact_plan",
            approval_request_reference=result.approval_request_reference,
            plan_digest=result.plan_digest,
        )
    evidence = PublicLiveLabCase(
        lab_level=LiveLabLevel.CORE,
        scenario=scenario,
        resource_type=spec.resource_type,
        operation_id=spec.operation_id,
        expected_status=spec.expected_status,
        observed_status=status.value,
        approximate_duration=_duration_bucket(time.monotonic() - started),
        classification=_classification(status),
        error_code=None,
        contract_digest=result.contract_digest,
        execution_state="passed" if status.value == spec.expected_status else "failed",
    )
    return CoreCaseInvocation(
        status=status,
        operator_action=result.operator_action,
        plan_digest=result.plan_digest,
        evidence=evidence,
    )
