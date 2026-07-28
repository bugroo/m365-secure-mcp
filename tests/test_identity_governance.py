from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp.contract_compiler import load_identity_candidate
from m365_secure_mcp.contract_manifest import (
    AsyncBehavior,
    AuthorizationMode,
    effect_model_digest,
    sha256_digest,
)
from m365_secure_mcp.governance import (
    GovernancePolicyError,
    GovernancePolicyV3,
    resolve_operation_governance,
)

from .operator_helpers import authority_record, synthetic_governance

ROOT = Path(__file__).resolve().parents[1]


def _policy(operation_id: str) -> tuple[GovernancePolicyV3, str]:
    manifest = load_identity_candidate(ROOT)
    contract = manifest.contract(operation_id)
    authority = authority_record(
        "identity-approver",
        "person-identity",
        "identity-key-2026",
        "identity",
        Ed25519PrivateKey.generate(),
    )
    base, _ = synthetic_governance(contract, (authority,))
    document = base.model_dump(mode="json")
    digest = sha256_digest(manifest)
    document["contract_manifest_digest"] = digest
    document["operations"]["contract_manifest_digest"] = digest
    if "membership" in operation_id:
        document["operations"]["operations"][0]["resource_fence_types"] = [
            "group",
            "tenant",
            "user",
        ]
    document["resources"]["groups"] = [
        "33333333-3333-4333-8333-333333333333"
    ]
    document["resources"]["allowed_sku_ids"] = [
        "44444444-4444-4444-8444-444444444444"
    ]
    document["resources"]["allowed_service_plan_ids"] = {
        "44444444-4444-4444-8444-444444444444": [
            "55555555-5555-4555-8555-555555555555"
        ]
    }
    return GovernancePolicyV3.model_validate(document), digest


@pytest.mark.parametrize(
    "operation_id",
    [
        "entra.user.sessions.revoke",
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
        "entra.user.direct_license.set",
    ],
)
def test_governance_v3_binds_every_identity_candidate(operation_id: str) -> None:
    policy, digest = _policy(operation_id)
    contract = load_identity_candidate(ROOT).contract(operation_id)
    effective = resolve_operation_governance(
        policy,
        contract,
        contract_manifest_digest=digest,
    )
    assert effective.operation_id == operation_id
    assert effective.authorization_mode is AuthorizationMode.EXPLICIT_PLAN
    assert effective.effect_model_digest == effect_model_digest()


def test_identity_governance_rejects_safety_binding_drift() -> None:
    policy, digest = _policy("entra.user.sessions.revoke")
    document = policy.model_dump(mode="json")
    document["operations"]["operations"][0]["async_behavior"] = (
        AsyncBehavior.SYNCHRONOUS.value
    )
    changed = GovernancePolicyV3.model_validate(document)
    with pytest.raises(
        GovernancePolicyError,
        match="safety binding",
    ):
        resolve_operation_governance(
            changed,
            load_identity_candidate(ROOT).contract(
                "entra.user.sessions.revoke"
            ),
            contract_manifest_digest=digest,
        )


def test_identity_governance_cannot_lower_t2_authorization() -> None:
    policy, _ = _policy("entra.user.account_state.set")
    document = policy.model_dump(mode="json")
    document["operations"]["operations"][0]["authorization_mode"] = (
        "standing_policy"
    )
    with pytest.raises(ValueError, match="authorization"):
        GovernancePolicyV3.model_validate(document)


def test_identity_resource_policy_is_closed_and_private() -> None:
    policy, _ = _policy("entra.user.direct_license.set")
    resources = policy.resources
    assert resources.synchronized_user_policy == "reject"
    assert len(resources.allowed_sku_ids) == 1
    document = resources.model_dump(mode="json")
    document["allowed_service_plan_ids"]["44444444-4444-4444-8444-444444444444"] = [
        "55555555-5555-4555-8555-555555555555",
        "55555555-5555-4555-8555-555555555555",
    ]
    with pytest.raises(ValueError, match="service plans"):
        type(resources).model_validate(document)
