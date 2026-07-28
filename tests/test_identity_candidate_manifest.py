from __future__ import annotations

import base64
import json
from datetime import date
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from m365_secure_mcp.contract_compiler import (
    check_outputs,
    compile_outputs,
    load_identity_candidate,
)
from m365_secure_mcp.contract_manifest import (
    ContractEffect,
    ContractLifecycleState,
    ContractSpecV2,
    authorize_candidate_activation,
    load_global_manifest,
    sha256_digest,
    sign_contract_manifest,
)
from m365_secure_mcp.contract_trust import (
    ContractSigningAuthority,
    SigningAuthorityClass,
    SigningKeyState,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_IDS = [
    "entra.user.sessions.revoke",
    "entra.user.account_state.set",
    "entra.group.user_membership.add",
    "entra.group.user_membership.remove",
    "entra.user.direct_license.set",
]


def _test_authority(signer: Ed25519PrivateKey) -> ContractSigningAuthority:
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return ContractSigningAuthority(
        key_id="test-m365-contracts-activation",
        public_key_b64=base64.b64encode(public).decode("ascii"),
        state=SigningKeyState.CURRENT,
        authority_class=SigningAuthorityClass.TEST,
        activated_on=date(2026, 7, 28),
    )


def test_candidate_manifest_is_complete_deterministic_and_not_registered() -> None:
    candidate = load_identity_candidate(ROOT)
    assert [item.id for item in candidate.contracts] == EXPECTED_IDS
    assert sha256_digest(candidate) == (
        "sha256:ffb663385285dc44d0756e87e9cc1e4ed72b129637fe6d02337c2244aa540399"
    )
    assert all(
        item.lifecycle_state is ContractLifecycleState.CANDIDATE
        and item.maturity.value == "preview"
        for item in candidate.contracts
    )
    active = load_global_manifest()
    assert not set(EXPECTED_IDS) & {item.id for item in active.contracts}
    assert check_outputs(compile_outputs(active, root=ROOT)) == []


def test_identity_candidate_has_exact_reviewed_graph_surface() -> None:
    candidate = load_identity_candidate(ROOT)
    assert {
        item.id: (item.graph.method, item.graph.endpoint, item.effect.value)
        for item in candidate.contracts
    } == {
        "entra.user.sessions.revoke": (
            "POST",
            "/users/{user_id}/revokeSignInSessions",
            "invoke_action",
        ),
        "entra.user.account_state.set": (
            "PATCH",
            "/users/{user_id}",
            "state_transition",
        ),
        "entra.group.user_membership.add": (
            "POST",
            "/groups/{group_id}/members/$ref",
            "relationship_add",
        ),
        "entra.group.user_membership.remove": (
            "DELETE",
            "/groups/{group_id}/members/{user_id}/$ref",
            "relationship_remove",
        ),
        "entra.user.direct_license.set": (
            "POST",
            "/users/{user_id}/assignLicense",
            "state_transition",
        ),
    }
    remove = candidate.contract("entra.group.user_membership.remove")
    assert remove.graph.endpoint.endswith("/$ref")
    assert remove.effect is ContractEffect.RELATIONSHIP_REMOVE
    serialized = json.dumps(candidate.model_dump(mode="json"))
    assert "/beta" not in serialized
    assert "Directory.ReadWrite.All" not in serialized
    assert "object_delete" not in {
        item.effect.value for item in candidate.contracts
    }


def test_identity_candidate_separates_permissions_and_roles() -> None:
    candidate = load_identity_candidate(ROOT)
    for contract in candidate.contracts:
        permissions = contract.permissions
        categorized = sorted(
            {
                *permissions.effect_delegated_scopes,
                *permissions.preflight_delegated_scopes,
                *permissions.readback_delegated_scopes,
                *permissions.protected_object_evidence_delegated_scopes,
            }
        )
        assert permissions.effect_delegated_scopes
        assert categorized == permissions.delegated_scopes
        assert permissions.microsoft_supported_roles
        assert permissions.project_required_role in (
            permissions.microsoft_supported_roles
        )
        assert permissions.operator_roles == [
            permissions.project_required_role
        ]
        assert permissions.project_role_rationale


def test_group_owner_is_documented_but_project_requires_groups_administrator() -> None:
    candidate = load_identity_candidate(ROOT)
    for contract_id in (
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
    ):
        permissions = candidate.contract(contract_id).permissions
        assert any(
            role.startswith("Group owner")
            for role in permissions.microsoft_supported_roles
        )
        assert permissions.project_required_role == "Groups Administrator"
        rationale = permissions.project_role_rationale or ""
        assert "token-subject" in rationale
        assert "TOCTOU" in rationale
        assert "live-lab" in rationale


def test_reviewed_workload_contract_rejects_incomplete_permission_metadata() -> None:
    source = load_identity_candidate(ROOT).contracts[0].model_dump(mode="json")
    source["permissions"]["effect_delegated_scopes"] = []
    with pytest.raises(ValidationError, match="effect permissions"):
        ContractSpecV2.model_validate(source)

    source = load_identity_candidate(ROOT).contracts[0].model_dump(mode="json")
    source["permissions"]["project_required_role"] = None
    with pytest.raises(ValidationError, match="supported and project roles"):
        ContractSpecV2.model_validate(source)


def test_unsigned_and_test_signed_candidate_cannot_activate() -> None:
    candidate = load_identity_candidate(ROOT)
    with pytest.raises(RuntimeError, match="unsigned"):
        authorize_candidate_activation(candidate, None)
    signer = Ed25519PrivateKey.generate()
    authority = _test_authority(signer)
    signature = sign_contract_manifest(
        candidate,
        signer,
        key_id=authority.key_id,
        authorities=(authority,),
        allow_test_authorities=True,
    )
    with pytest.raises(RuntimeError, match="test contract authority"):
        authorize_candidate_activation(
            candidate,
            signature,
            authorities=(authority,),
            allow_test_authorities=True,
        )


def test_relationship_remove_cannot_become_object_delete() -> None:
    source = load_identity_candidate(ROOT).contract(
        "entra.group.user_membership.remove"
    ).model_dump(mode="json")
    for endpoint in (
        "/groups/{group_id}/members/{user_id}",
        "/groups/{group_id}/members/{user_id}/%24ref",
        "/groups/{group_id}/members/{user_id}/{suffix}",
        "/groups/{group_id}/members/{user_id}/../$ref",
    ):
        changed = dict(source)
        changed["graph"] = {
            "method": "DELETE",
            "endpoint": endpoint,
            "api_version": "v1.0",
        }
        with pytest.raises(ValidationError):
            ContractSpecV2.model_validate(changed)
    changed = dict(source)
    changed["effect"] = "object_delete"
    with pytest.raises(ValidationError):
        ContractSpecV2.model_validate(changed)


def test_candidate_rejects_caller_controlled_graph_fields() -> None:
    source = load_identity_candidate(ROOT).contracts[0].model_dump(mode="json")
    source["input_schema"]["properties"]["url"] = {"type": "string"}
    with pytest.raises(ValidationError, match="caller-controlled"):
        ContractSpecV2.model_validate(source)


def test_candidate_artifacts_are_public_and_signature_free() -> None:
    paths = [
        ROOT / "contract-candidates/generated-registry.json",
        ROOT / "contract-candidates/graph-surface-diff.json",
        ROOT / "contract-candidates/provenance.json",
        ROOT / "contract-candidates/sbom-binding.json",
        ROOT / "contract-candidates/signing-request.json",
    ]
    content = "\n".join(path.read_text() for path in paths)
    assert '"signature_present": false' in content
    assert "BEGIN PRIVATE KEY" not in content
    assert "BEGIN ENCRYPTED PRIVATE KEY" not in content
    assert "werixo.internal" not in content.lower()
    assert "pending-external-inspection" in content


def test_signing_request_requires_live_lab_and_separate_activation_pr() -> None:
    request = json.loads(
        (ROOT / "contract-candidates/signing-request.json").read_text()
    )
    assert request["status"] == "awaiting_reviewed_live_lab"
    assert request["signing_eligible"] is False
    assert request["candidate_tool_registration"] is False
    assert request["digest_invalidated_by_candidate_change"] is True
    assert request["activation_sequence"] == [
        "merge-inactive-candidate-pr",
        "execute-and-review-live-lab-for-all-five-operations",
        "apply-corrections-and-regenerate-candidate-digest-if-needed",
        "sign-final-reviewed-digest-with-external-production-authority",
        "merge-separate-small-activation-pr",
    ]
