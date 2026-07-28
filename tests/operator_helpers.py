"""Synthetic-only fixtures for Operator Foundation tests."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    ContractEffect,
    ContractManifestV2,
    ContractPermissions,
    ContractSpecV2,
    EffectGraphCall,
    GraphCall,
    IdempotencyContract,
    RiskTier,
    VerificationMode,
    effect_model_digest,
    sha256_digest,
)
from m365_secure_mcp.governance import (
    ApprovalAuthorityBinding,
    AsyncRequirement,
    GovernancePolicyV3,
    GovernanceProfile,
    GovernanceProfileName,
    GovernanceResources,
    OperationGovernanceBinding,
    OperationsGovernance,
    ProtectedObjectPolicy,
    ResourceFenceType,
    resolve_operation_governance,
)
from m365_secure_mcp.operator_authority import ApprovalAuthorityRecord

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
USER_ID = UUID("22222222-2222-4222-8222-222222222222")
OPERATOR_ID = UUID("33333333-3333-4333-8333-333333333333")
DEPLOYMENT_NAMESPACE = "0123456789abcdef"
NOW = datetime(2026, 7, 28, 10, 0, tzinfo=UTC)


def synthetic_contract(
    *,
    risk_tier: RiskTier = RiskTier.T2,
    authorization_mode: AuthorizationMode = AuthorizationMode.EXPLICIT_PLAN,
    verification: VerificationMode = VerificationMode.STRONG_READBACK,
) -> ContractSpecV2:
    return ContractSpecV2(
        id="synthetic.user.state_transition",
        tool_name="m365_synthetic_user_state_transition",
        description=(
            "Synthetic fixture contract proving governed state-transition semantics."
        ),
        module="synthetic",
        graph=EffectGraphCall(
            method="PATCH",
            endpoint="/users/{user_id}",
            api_version="v1.0",
        ),
        preflight_graph_calls=[
            GraphCall(
                method="GET",
                endpoint="/users/{user_id}",
                api_version="v1.0",
            )
        ],
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["desired_state", "user_id"],
            "properties": {
                "desired_state": {"type": "boolean"},
                "user_id": {"type": "string", "format": "uuid"},
            },
        },
        output_fields=["evidence_reference", "status"],
        permissions=ContractPermissions(
            delegated_scopes=["User.ReadUpdate.All"],
            operator_roles=["User Administrator"],
            admin_consent_required=True,
        ),
        risk_tier=risk_tier,
        authorization_mode=authorization_mode,
        resource_fences=["tenant_id", "user_id"],
        preconditions=["target_allowlisted", "target_not_protected"],
        postconditions=["desired_state_observed"],
        plan_ttl_seconds=300,
        idempotency=IdempotencyContract(
            key_required=True,
            retry="never_after_uncertain",
        ),
        verification=verification,
        compensation=CompensationClass.CONDITIONAL_RESTORE,
        effect=ContractEffect.STATE_TRANSITION,
    )


def authority_record(
    authority_id: str,
    identity_id: str,
    key_id: str,
    signer_group: str,
    signer: Ed25519PrivateKey,
    **updates: object,
) -> ApprovalAuthorityRecord:
    raw = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    values: dict[str, object] = {
        "authority_id": authority_id,
        "identity_id": identity_id,
        "key_id": key_id,
        "signer_group": signer_group,
        "public_key_b64": base64.b64encode(raw).decode("ascii"),
        "state": "active",
        "activated_at": NOW - timedelta(days=30),
    }
    values.update(updates)
    return ApprovalAuthorityRecord.model_validate(values)


def authority_binding(record: ApprovalAuthorityRecord) -> ApprovalAuthorityBinding:
    raw = base64.b64decode(record.public_key_b64, validate=True)
    return ApprovalAuthorityBinding(
        authority_id=record.authority_id,
        identity_id=record.identity_id,
        key_id=record.key_id,
        signer_group=record.signer_group,
        public_key_sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
    )


def synthetic_governance(
    contract: ContractSpecV2,
    authorities: tuple[ApprovalAuthorityRecord, ...],
    *,
    risk_tier: RiskTier | None = None,
    authorization_mode: AuthorizationMode | None = None,
) -> tuple[GovernancePolicyV3, str]:
    manifest = ContractManifestV2(
        schema_version="2.0",
        product="m365-secure-mcp",
        contracts=[contract],
    )
    manifest_digest = sha256_digest(manifest)
    tier = risk_tier or contract.risk_tier
    mode = authorization_mode or contract.authorization_mode
    selected_contracts = [contract.id]
    profiles = {
        GovernanceProfileName.ROUTINE_READ: GovernanceProfile(),
        GovernanceProfileName.ROUTINE_WRITE: GovernanceProfile(),
        GovernanceProfileName.PRIVILEGED_READ: GovernanceProfile(),
        GovernanceProfileName.SELECTED_WRITE: GovernanceProfile(
            enabled_contracts=selected_contracts
        ),
        GovernanceProfileName.BREAK_GLASS: GovernanceProfile(
            break_glass_ttl_seconds=900
        ),
    }
    authority_bindings = sorted(
        (authority_binding(item) for item in authorities),
        key=lambda item: item.authority_id,
    )
    required_groups = sorted(
        {item.signer_group for item in authority_bindings}
    )
    if mode is AuthorizationMode.EXPLICIT_PLAN:
        required_groups = required_groups[:1]
    policy = GovernancePolicyV3(
        tenant_id=TENANT_ID,
        active_profile=GovernanceProfileName.SELECTED_WRITE,
        profiles=profiles,
        resources=GovernanceResources(
            tenants=[TENANT_ID],
            users=[USER_ID],
            protected_user_ids=[],
        ),
        contract_manifest_digest=manifest_digest,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        operations=OperationsGovernance(
            contract_manifest_digest=manifest_digest,
            contract_manifest_schema_versions=["2.0"],
            effect_model_schema_version="1.0",
            effect_model_digest=effect_model_digest(),
            approval_authorities=authority_bindings,
            operations=[
                OperationGovernanceBinding(
                    operation_id=contract.id,
                    contract_id=contract.id,
                    contract_digest=sha256_digest(contract),
                    effect=contract.effect,
                    minimum_risk_tier=tier,
                    authorization_mode=mode,
                    resource_fence_types=[
                        ResourceFenceType.TENANT,
                        ResourceFenceType.USER,
                    ],
                    protected_object_policy=(
                        ProtectedObjectPolicy.EXCLUDE_PROTECTED
                    ),
                    async_requirement=AsyncRequirement.SYNCHRONOUS_ONLY,
                    verification=contract.verification,
                    approval_authority_ids=[
                        item.authority_id for item in authority_bindings
                    ],
                    required_signer_groups=required_groups,
                )
            ],
        ),
    )
    return policy, manifest_digest


def effective_governance(
    contract: ContractSpecV2,
    authorities: tuple[ApprovalAuthorityRecord, ...],
    *,
    risk_tier: RiskTier | None = None,
    authorization_mode: AuthorizationMode | None = None,
):
    policy, manifest_digest = synthetic_governance(
        contract,
        authorities,
        risk_tier=risk_tier,
        authorization_mode=authorization_mode,
    )
    return resolve_operation_governance(
        policy,
        contract,
        contract_manifest_digest=manifest_digest,
    )
