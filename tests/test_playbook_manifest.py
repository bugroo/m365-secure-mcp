from __future__ import annotations

import json
from pathlib import Path

import pytest

import m365_secure_mcp.playbook_manifest as playbook_module
from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    CompensationClass,
    RiskTier,
    load_global_manifest,
)
from m365_secure_mcp.playbook_manifest import load_global_playbook_manifest


def test_signed_workload_readiness_playbook_has_fixed_t0_closure() -> None:
    contracts = load_global_manifest()
    manifest = load_global_playbook_manifest(contracts)
    playbook = manifest.playbook(
        "entra.workload_identity.readiness.playbook"
    )

    assert playbook.tool_name == "m365_get_entra_workload_identity_readiness"
    assert playbook.risk_tier is RiskTier.T0
    assert playbook.authorization_mode is AuthorizationMode.AUTOMATIC_READ
    assert playbook.compensation is CompensationClass.NOT_APPLICABLE
    assert playbook.writes_permitted is False
    assert [node.contract_id for node in playbook.ordered_nodes()] == [
        "entra.app_credentials.posture.snapshot",
        "entra.permission_grants.drift.snapshot",
    ]
    assert playbook.delegated_scope_closure(contracts) == [
        "Application.Read.All",
        "Directory.Read.All",
    ]
    assert all(
        contracts.contract(node.contract_id).graph.method == "GET"
        for node in playbook.nodes
    )


def test_playbook_signature_fails_closed_after_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contracts = load_global_manifest()
    original_data_bytes = playbook_module._data_bytes

    def tampered_data_bytes(name: str) -> bytes:
        payload = original_data_bytes(name)
        if name != "global-playbooks.json":
            return payload
        document = json.loads(payload)
        document["playbooks"][0]["description"] += " tampered"
        return json.dumps(document).encode()

    monkeypatch.setattr(
        playbook_module,
        "_data_bytes",
        tampered_data_bytes,
    )
    with pytest.raises(RuntimeError, match="digest mismatch"):
        load_global_playbook_manifest(contracts)


def test_playbook_public_artifacts_contain_no_test_tenant_identifiers() -> None:
    root = Path(__file__).resolve().parents[1]
    public_paths = [
        root / "src/m365_secure_mcp/contract_data/global-playbooks.json",
        root / "contract-artifacts/playbook-digests.json",
        root / "contract-artifacts/playbook-tests.json",
        root / "contract-artifacts/provenance.json",
        root / "docs/PLAYBOOK_MATRIX.md",
    ]
    payload = "\n".join(path.read_text() for path in public_paths)
    assert "11111111-1111-4111-8111-111111111111" not in payload
    assert "33333333-3333-4333-8333-333333333333" not in payload


def test_playbook_never_accepts_graph_or_approval_arguments() -> None:
    contracts = load_global_manifest()
    manifest = load_global_playbook_manifest(contracts)
    for playbook in manifest.playbooks:
        assert playbook.writes_permitted is False
        assert {
            "endpoint",
            "method",
            "url",
            "headers",
            "tenant_id",
            "approved",
            "approval",
        }.isdisjoint(playbook.output_fields)
