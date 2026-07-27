from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import m365_secure_mcp.control_manifest as control_module
from m365_secure_mcp._generated_controls import (
    CONTROL_DEFINITIONS,
    CONTROL_FRAMEWORK_MAPPINGS,
    CONTROL_FRAMEWORK_SOURCES,
    CONTROL_MANIFEST_DIGEST,
)
from m365_secure_mcp.contract_compiler import check_outputs, compile_outputs
from m365_secure_mcp.contract_manifest import load_global_manifest, sha256_digest
from m365_secure_mcp.contract_trust import CONTROL_SIGNING_AUTHORITIES
from m365_secure_mcp.control_manifest import (
    ControlDefinition,
    ControlLifecycleState,
    ControlManifest,
    load_global_control_manifest,
    validate_lifecycle_transition,
)
from m365_secure_mcp.playbook_manifest import load_global_playbook_manifest

ROOT = Path(__file__).resolve().parents[1]
CONTROL_PATH = (
    ROOT
    / "src/m365_secure_mcp/contract_data/global-controls.json"
)
CANONICAL_CONTROL_IDS = [
    "entra.applications.active_credential_count",
    "entra.applications.credential_expiry_posture",
    "entra.applications.owner_coverage",
    "entra.applications.password_credential_policy",
    "entra.applications.permission_contract_closure",
    "entra.conditional_access.mfa_policy_coverage",
    "entra.directory_roles.permanent_active_assignment",
    "entra.profiles.contract_closure",
    "entra.profiles.resource_fence_closure",
    "entra.profiles.scope_closure",
]
FROZEN_GRAPH_ARTIFACT_HASHES = {
    "src/m365_secure_mcp/contract_data/global-manifest.json": (
        "5fc7cd7b99f24e5c865280bdbdec6b49020346ac794997c07fce61ea7623a1ee"
    ),
    "src/m365_secure_mcp/contract_data/global-manifest.sig.json": (
        "6298f1c4fb0ffbc04d282830d2aced4a3fd7f26981dea86088d67944d28403c3"
    ),
    "src/m365_secure_mcp/contract_data/global-playbooks.json": (
        "90483d9a2a8b87a41ec89151533149ede1adf1a55085e0b4ef00272e52b6470c"
    ),
    "src/m365_secure_mcp/contract_data/global-playbooks.sig.json": (
        "c7978ac764953ab58176c3d56b8af89699195a2ef5a73c072744409c799e84da"
    ),
    "docs/CONTRACT_MATRIX.md": (
        "39e1184145cbe06c0abdc9e0000f875af982c78d2d1980c5028829c16d61f5f2"
    ),
    "docs/PLAYBOOK_MATRIX.md": (
        "ec583a66f14ebbc33d7a1a8748492cea214177cd72d3405238948dbb3bc78de1"
    ),
    "contract-artifacts/contract-digests.json": (
        "74db27431ca26e361fe38e67bb41bbf3c997f90ade395e717bdfdccf50df472e"
    ),
    "contract-artifacts/playbook-digests.json": (
        "539d393c49dece88c5ea71ebea1185f44f8a49a6835fa2f0404dc928f3028f32"
    ),
}


def _raw_manifest() -> dict[str, Any]:
    document = json.loads(CONTROL_PATH.read_text())
    assert isinstance(document, dict)
    return document


def _definition_with_lifecycle(
    definition: ControlDefinition,
    *,
    state: str,
    definition_version: str = "1.0.0",
    description: str | None = None,
) -> ControlDefinition:
    document = definition.model_dump(mode="json")
    document["definition_version"] = definition_version
    document["description"] = description or definition.description
    document["lifecycle"] = {
        "state": state,
        "introduced_in_library_version": "1.0.0",
        "deprecated_at": (
            "2026-08-01"
            if state in {"deprecated", "retired"}
            else None
        ),
        "retired_at": "2026-09-01" if state == "retired" else None,
        "successor_control_id": None,
    }
    return ControlDefinition.model_validate(document)


def test_signed_control_manifest_compiles_to_committed_artifacts() -> None:
    contracts = load_global_manifest()
    playbooks = load_global_playbook_manifest(contracts)
    controls = load_global_control_manifest()

    assert [item.control_id for item in controls.controls] == CANONICAL_CONTROL_IDS
    assert check_outputs(
        compile_outputs(
            contracts,
            root=ROOT,
            playbooks=playbooks,
            controls=controls,
        )
    ) == []


def test_unsigned_manifest_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = control_module._data_bytes

    def without_signature(name: str) -> bytes:
        if name == "global-controls.sig.json":
            raise OSError("signature deliberately unavailable")
        return original(name)

    monkeypatch.setattr(control_module, "_data_bytes", without_signature)
    with pytest.raises(RuntimeError, match="malformed or unsigned"):
        load_global_control_manifest()


def test_tampered_manifest_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = control_module._data_bytes

    def tampered(name: str) -> bytes:
        payload = original(name)
        if name != "global-controls.json":
            return payload
        document = json.loads(payload)
        document["controls"][0]["description"] += " tampered"
        return json.dumps(document).encode()

    monkeypatch.setattr(control_module, "_data_bytes", tampered)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        load_global_control_manifest()


def test_wrong_signing_key_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_public_key = base64.b64encode(bytes(32)).decode("ascii")
    monkeypatch.setattr(
        control_module,
        "CONTROL_SIGNING_AUTHORITIES",
        (
            replace(
                CONTROL_SIGNING_AUTHORITIES[0],
                public_key_b64=wrong_public_key,
            ),
        ),
    )
    with pytest.raises(RuntimeError, match="signature is invalid"):
        load_global_control_manifest()


def test_unknown_evaluator_id_is_rejected() -> None:
    document = _raw_manifest()
    document["controls"][0]["evaluator_id"] = "DYNAMIC_EXPRESSION_V1"
    with pytest.raises(ValidationError, match="evaluator_id"):
        ControlManifest.model_validate(document)


def test_duplicated_control_id_is_rejected() -> None:
    document = _raw_manifest()
    document["controls"][1]["control_id"] = document["controls"][0]["control_id"]
    with pytest.raises(ValidationError, match="control IDs must be unique"):
        ControlManifest.model_validate(document)


def test_invalid_lifecycle_transition_is_rejected() -> None:
    definition = load_global_control_manifest().controls[0]
    retired = _definition_with_lifecycle(definition, state="retired")

    with pytest.raises(ValueError, match="invalid control lifecycle transition"):
        validate_lifecycle_transition(definition, retired)


def test_retired_id_cannot_be_reused() -> None:
    definition = load_global_control_manifest().controls[0]
    retired = _definition_with_lifecycle(definition, state="retired")
    reused = _definition_with_lifecycle(
        definition,
        state="retired",
        definition_version="1.0.1",
        description=f"{definition.description} Replacement semantics.",
    )

    with pytest.raises(ValueError, match="permanently reserved"):
        validate_lifecycle_transition(retired, reused)


def test_definitions_cannot_contain_severity_or_private_selectors() -> None:
    severity = _raw_manifest()
    severity["controls"][0]["severity"] = "critical"
    with pytest.raises(ValidationError, match="severity"):
        ControlManifest.model_validate(severity)

    tenant_selector = _raw_manifest()
    tenant_selector["controls"][0]["tenant_ids"] = ["private"]
    with pytest.raises(ValidationError, match="tenant_ids"):
        ControlManifest.model_validate(tenant_selector)


@pytest.mark.parametrize(
    "private_text",
    [
        "Tenant 11111111-1111-4111-8111-111111111111",
        "Operator person@example.com",
        "Source network 192.0.2.20",
    ],
)
def test_public_definition_text_rejects_private_identifiers(
    private_text: str,
) -> None:
    document = _raw_manifest()
    document["controls"][0]["description"] = private_text
    with pytest.raises(ValidationError, match="private identifiers|IP addresses"):
        ControlManifest.model_validate(document)


def test_unverified_mapping_cannot_be_published() -> None:
    document = _raw_manifest()
    document["mappings"][0]["verification_status"] = "unverified"
    with pytest.raises(
        ValidationError,
        match="unverified framework mappings cannot be published",
    ):
        ControlManifest.model_validate(document)

    document = _raw_manifest()
    source_id = document["mappings"][0]["source_id"]
    source = next(
        item for item in document["sources"] if item["source_id"] == source_id
    )
    source["verification_status"] = "unverified"
    with pytest.raises(
        ValidationError,
        match="published mapping cannot use an unverified framework source",
    ):
        ControlManifest.model_validate(document)


def test_canonical_serialization_normalizes_permutations() -> None:
    original = _raw_manifest()
    permuted = _raw_manifest()
    permuted["controls"].reverse()
    permuted["sources"].reverse()
    permuted["mappings"].reverse()
    for control in permuted["controls"]:
        control["mapping_ids"].reverse()
        control["limitation_codes"].reverse()
        control["evidence_requirements"].reverse()
        for requirement in control["evidence_requirements"]:
            requirement["evidence_domains"].reverse()

    first = ControlManifest.model_validate(original)
    second = ControlManifest.model_validate(permuted)
    assert first == second
    assert sha256_digest(first) == sha256_digest(second)


def test_generated_registry_matches_signed_manifest() -> None:
    manifest = load_global_control_manifest()
    assert CONTROL_MANIFEST_DIGEST == sha256_digest(manifest)
    assert set(CONTROL_DEFINITIONS) == set(CANONICAL_CONTROL_IDS)
    assert set(CONTROL_FRAMEWORK_SOURCES) == {
        item.source_id for item in manifest.sources
    }
    assert set(CONTROL_FRAMEWORK_MAPPINGS) == {
        item.mapping_id for item in manifest.mappings if item.published
    }
    for control in manifest.controls:
        generated = CONTROL_DEFINITIONS[control.control_id]
        assert generated["evaluator_id"] == control.evaluator_id.value
        assert generated["definition_version"] == control.definition_version


def test_graph_contract_playbook_and_permission_artifacts_are_frozen() -> None:
    for relative_path, expected in FROZEN_GRAPH_ARTIFACT_HASHES.items():
        actual = hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest()
        assert actual == expected


def test_global_manifest_has_no_dynamic_rule_or_customer_namespace() -> None:
    payload = CONTROL_PATH.read_text().lower()
    assert "werixo.internal" not in payload
    assert "severity" not in payload
    assert all(
        term not in payload
        for term in (
            "\"expression\"",
            "\"python\"",
            "\"cel\"",
            "\"jmespath\"",
            "\"tenant_id\"",
            "\"object_id\"",
            "\"user_principal_name\"",
        )
    )
    assert all(
        control.lifecycle.state is ControlLifecycleState.ACTIVE
        for control in load_global_control_manifest().controls
    )
