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
    compile_identity_candidate_outputs,
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
from m365_secure_mcp.identity_live_lab import LIVE_LAB_SCENARIO_CONTRACTS

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_IDS = [
    "entra.user.sessions.revoke",
    "entra.user.account_state.set",
    "entra.group.user_membership.add",
    "entra.group.user_membership.remove",
    "entra.user.direct_license.set",
]
EXPECTED_PUBLIC_OUTPUT_FIELDS = [
    "approval_request_reference",
    "change_record_reference",
    "contract_digest",
    "contract_id",
    "evidence_reference",
    "operation_reference",
    "operator_action",
    "observation_reference",
    "plan_digest",
    "receipt_reference",
    "safe_to_retry",
    "status",
    "verification",
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
        "sha256:788bb37c79af5363056d7e8ef661087098c64fb1073b05dfa0cdb177a7e16e65"
    )
    for contract in candidate.contracts:
        assert contract.idempotency.key_required is True
        assert "idempotency_key" in contract.input_schema["properties"]
        assert "idempotency_key" in contract.input_schema["required"]
        assert contract.output_fields == EXPECTED_PUBLIC_OUTPUT_FIELDS
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
        assert permissions.microsoft_supported_evidence_roles
        assert permissions.project_required_evidence_role in (
            permissions.microsoft_supported_evidence_roles
        )
        assert permissions.operator_roles == sorted(
            {
                permissions.project_required_role,
                permissions.project_required_evidence_role,
            }
        )
        assert permissions.project_role_rationale
        assert permissions.project_evidence_role_rationale


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
    with pytest.raises(ValidationError, match="effect and evidence roles"):
        ContractSpecV2.model_validate(source)

    source = load_identity_candidate(ROOT).contracts[0].model_dump(mode="json")
    source["permissions"]["project_required_evidence_role"] = None
    with pytest.raises(ValidationError, match="effect and evidence roles"):
        ContractSpecV2.model_validate(source)


def test_identity_candidate_requires_global_reader_for_protection_evidence() -> None:
    candidate = load_identity_candidate(ROOT)
    for contract in candidate.contracts:
        permissions = contract.permissions
        assert permissions.project_required_evidence_role == "Global Reader"
        assert "Global Reader" in permissions.microsoft_supported_evidence_roles
        assert "Privileged Role Administrator" in (
            permissions.microsoft_supported_evidence_roles
        )


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
    assert request["status"] == "awaiting_reviewed_core_identity_lab"
    assert request["signing_eligible"] is False
    assert request["candidate_tool_registration"] is False
    assert request["digest_invalidated_by_candidate_change"] is True
    assert request["activation_sequence"] == [
        "merge-inactive-candidate-pr",
        "provision-core-identity-lab",
        "execute-five-operations-with-isolated-operator-profiles",
        "apply-corrections-and-regenerate-candidate-digest-if-needed",
        "sign-final-reviewed-digest-with-external-production-authority",
        "merge-separate-small-activation-pr",
        "complete-extended-identity-lab-before-stable",
    ]
    assert (
        "extended-live-lab-required-before-stable"
        in request["tests_required"]
    )
    assert request["artifact_digests"]["live_lab_evidence"] is None


def test_reviewed_core_evidence_is_content_bound_before_signing(
    tmp_path: Path,
) -> None:
    candidate = load_identity_candidate(ROOT)
    root = tmp_path / "build"
    (root / "contract-candidates").mkdir(parents=True)
    (root / "contract-artifacts").mkdir()
    (root / "contract-artifacts/sbom.cdx.json").write_text("{}")
    cases = []
    for scenario, (
        level,
        operation_id,
        resource_type,
        expected_status,
    ) in sorted(LIVE_LAB_SCENARIO_CONTRACTS.items()):
        executed = level == "core"
        cases.append(
            {
                "lab_level": level,
                "scenario": scenario,
                "resource_type": resource_type,
                "operation_id": operation_id,
                "expected_status": expected_status,
                "observed_status": expected_status if executed else "NOT_EXECUTED",
                "approximate_duration": "1_to_5s",
                "classification": (
                    {
                        "BLOCKED_PRECONDITION": "blocked",
                        "EXECUTED_ACCEPTED": "accepted",
                        "EXECUTED_UNCERTAIN": "uncertain",
                        "EXECUTED_VERIFIED": "verified",
                    }[expected_status]
                    if executed
                    else "blocked"
                ),
                "error_code": None,
                "contract_digest": sha256_digest(
                    candidate.contract(operation_id)
                ),
                "execution_state": "passed" if executed else "not_executed",
            }
        )
    evidence = {
        "schema_version": "2.0",
        "evidence_kind": "sanitized-identity-live-lab",
        "contains_customer_data": False,
        "candidate_manifest_digest": sha256_digest(candidate),
        "cases": cases,
    }
    (root / "contract-candidates/identity-live-lab-evidence.json").write_text(
        json.dumps(evidence)
    )
    outputs = compile_identity_candidate_outputs(
        candidate,
        active_manifest=load_global_manifest(),
        root=root,
    )
    request = json.loads(
        outputs[
            root / "contract-candidates/signing-request.json"
        ]
    )
    assert request["signing_eligible"] is True
    assert request["status"] == "ready_for_external_signing"
    assert request["artifact_digests"]["live_lab_evidence"].startswith(
        "sha256:"
    )
