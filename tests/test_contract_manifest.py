from __future__ import annotations

import json
from pathlib import Path

import pytest

import m365_secure_mcp.contract_manifest as manifest_module
from m365_secure_mcp.contract_compiler import check_outputs, compile_outputs
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    RiskTier,
    VerificationMode,
    load_global_manifest,
)


def test_signed_manifest_compiles_to_committed_artifacts() -> None:
    manifest = load_global_manifest()
    root = Path(__file__).resolve().parents[1]
    assert check_outputs(compile_outputs(manifest, root=root)) == []


def test_t1_contract_has_exact_bounded_surface() -> None:
    contract = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    )
    assert contract.graph.method == "PATCH"
    assert contract.graph.endpoint == "/users/{user_id}"
    assert set(contract.input_schema["properties"]) == {
        "user_id",
        "idempotency_key",
        "department",
        "job_title",
        "office_location",
    }
    assert contract.permissions.delegated_scopes == [
        "GroupMember.Read.All",
        "RoleManagement.Read.Directory",
        "User.ReadUpdate.All",
    ]
    assert contract.permissions.operator_roles == [
        "Global Reader",
        "User Administrator",
    ]
    assert contract.risk_tier is RiskTier.T1
    assert contract.authorization_mode is AuthorizationMode.STANDING_POLICY
    assert contract.verification is VerificationMode.STRONG_READBACK
    assert contract.idempotency.retry == "never_after_uncertain"
    assert {
        call.endpoint for call in contract.preflight_graph_calls
    } >= {
        "/roleManagement/directory/roleAssignments",
        "/roleManagement/directory/roleAssignmentScheduleInstances",
        "/roleManagement/directory/roleEligibilityScheduleInstances",
    }
    assert "Directory.ReadWrite.All" not in contract.permissions.delegated_scopes
    assert "User.ReadWrite.All" not in contract.permissions.delegated_scopes


def test_assurance_contract_is_fixed_t0_and_read_only() -> None:
    contract = load_global_manifest().contract(
        "entra.identity_governance.posture.snapshot"
    )
    assert contract.graph.method == "GET"
    assert contract.graph.endpoint == "/identity/conditionalAccess/policies"
    assert contract.input_schema["properties"] == {}
    assert contract.permissions.delegated_scopes == [
        "Policy.Read.All",
        "RoleManagement.Read.Directory",
    ]
    assert contract.permissions.operator_roles == ["Global Reader"]
    assert contract.risk_tier is RiskTier.T0
    assert contract.authorization_mode is AuthorizationMode.AUTOMATIC_READ
    assert contract.verification is VerificationMode.RESOURCE_OBSERVED
    assert {
        call.endpoint for call in contract.preflight_graph_calls
    } == {
        "/roleManagement/directory/roleAssignments",
        "/roleManagement/directory/roleAssignmentScheduleInstances",
        "/roleManagement/directory/roleEligibilityScheduleInstances",
    }
    assert contract.idempotency.retry == "bounded_read_retry"


def test_manifest_signature_fails_closed_after_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_data_bytes = manifest_module._data_bytes

    def tampered_data_bytes(name: str) -> bytes:
        payload = original_data_bytes(name)
        if name != "global-manifest.json":
            return payload
        document = json.loads(payload)
        document["contracts"][0]["description"] += " tampered"
        return json.dumps(document).encode()

    monkeypatch.setattr(manifest_module, "_data_bytes", tampered_data_bytes)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        load_global_manifest()


def test_public_contract_artifacts_contain_no_test_tenant_identifiers() -> None:
    root = Path(__file__).resolve().parents[1]
    public_paths = [
        root / "src/m365_secure_mcp/contract_data/global-manifest.json",
        root / "src/m365_secure_mcp/contract_data/global-playbooks.json",
        root / "contract-artifacts/contract-digests.json",
        root / "contract-artifacts/contract-tests.json",
        root / "contract-artifacts/playbook-digests.json",
        root / "contract-artifacts/playbook-tests.json",
        root / "contract-artifacts/provenance.json",
        root / "contract-artifacts/sbom.cdx.json",
        root / "src/m365_secure_mcp/release_data/contract-digests.json",
        root / "src/m365_secure_mcp/release_data/playbook-digests.json",
        root / "src/m365_secure_mcp/release_data/provenance.json",
        root / "src/m365_secure_mcp/release_data/sbom.cdx.json",
        root / "docs/CONTRACT_MATRIX.md",
        root / "docs/PLAYBOOK_MATRIX.md",
    ]
    payload = "\n".join(path.read_text() for path in public_paths)
    assert "11111111-1111-4111-8111-111111111111" not in payload
    assert "33333333-3333-4333-8333-333333333333" not in payload


def test_contracts_never_accept_a_graph_path_or_method_as_input() -> None:
    for contract in load_global_manifest().contracts:
        fields = set(contract.input_schema["properties"])
        assert fields.isdisjoint(
            {"endpoint", "graph_endpoint", "method", "url", "headers"}
        )
        assert contract.graph.api_version in {None, "v1.0"}


def test_sbom_uses_resolved_versions_from_uv_lock() -> None:
    root = Path(__file__).resolve().parents[1]
    sbom = json.loads((root / "contract-artifacts/sbom.cdx.json").read_text())
    cryptography = next(
        item for item in sbom["components"] if item["name"] == "cryptography"
    )
    assert cryptography["version"] == "49.0.0"
    assert cryptography["purl"] == "pkg:pypi/cryptography@49.0.0"
