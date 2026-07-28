from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from m365_secure_mcp.contract_manifest import (
    ContractEffect,
    ContractSpec,
    ContractSpecV2,
    canonical_json,
    contract_effect,
    effect_model_digest,
    effect_model_document,
    load_global_manifest,
    sha256_digest,
)
from m365_secure_mcp.playbook_manifest import load_global_playbook_manifest

CONTRACT_MANIFEST_DIGEST = (
    "sha256:1a33a244371405402df75a125fe6c18a9d6d0af0d2b692f5a831cde82248f5ba"
)
PLAYBOOK_MANIFEST_DIGEST = (
    "sha256:13a3dada2e106bc8f56f35301e4b57e601a75668adebe73be07b829d39819ca4"
)


def _future_contract(
    *,
    effect: str,
    method: str,
    endpoint: str,
    extra_input_field: str | None = None,
) -> dict[str, Any]:
    base = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    ).model_dump(mode="json")
    base.update(
        {
            "id": "entra.group.user_membership.remove",
            "tool_name": "m365_remove_exact_group_membership",
            "description": (
                "Future test-only exact relationship removal contract."
            ),
            "module": "synthetic",
            "graph": {
                "method": method,
                "endpoint": endpoint,
                "api_version": "v1.0",
            },
            "preflight_graph_calls": [],
            "effect": effect,
            "risk_tier": "T2",
            "authorization_mode": "explicit_plan",
            "resource_fences": ["exact_group", "exact_member"],
        }
    )
    properties = {
        "directory_object_id": {"type": "string", "format": "uuid"},
        "group_id": {"type": "string", "format": "uuid"},
    }
    if extra_input_field is not None:
        properties[extra_input_field] = {"type": "string"}
    base["input_schema"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": ["directory_object_id", "group_id"],
    }
    return base


def test_existing_signed_contracts_have_closed_legacy_effects() -> None:
    effects = {
        contract.id: contract_effect(contract)
        for contract in load_global_manifest().contracts
    }
    assert effects["entra.user.operational_profile.update"] is (
        ContractEffect.UPDATE_PROPERTIES
    )
    assert all(
        effect is ContractEffect.READ
        for contract_id, effect in effects.items()
        if contract_id != "entra.user.operational_profile.update"
    )


def test_schema_1_0_rejects_ambiguous_post_effect() -> None:
    candidate = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    ).model_dump(mode="json")
    candidate["graph"] = {
        "method": "POST",
        "endpoint": "/users/{user_id}",
        "api_version": "v1.0",
    }
    with pytest.raises(
        ValidationError,
        match="schema 1.0 cannot infer a safe semantic effect for POST",
    ):
        ContractSpec.model_validate(candidate)


def test_unknown_effect_is_rejected() -> None:
    with pytest.raises(ValidationError, match="effect"):
        ContractSpecV2.model_validate(
            _future_contract(
                effect="execute_whatever",
                method="DELETE",
                endpoint=(
                    "/groups/{group_id}/members/"
                    "{directory_object_id}/$ref"
                ),
            )
        )


def test_object_delete_is_always_rejected() -> None:
    candidate = _future_contract(
        effect="object_delete",
        method="DELETE",
        endpoint="/users/{user_id}",
    )
    candidate["risk_tier"] = "T4"
    candidate["authorization_mode"] = "prohibited"
    with pytest.raises(ValidationError, match="object_delete contracts are prohibited"):
        ContractSpecV2.model_validate(candidate)


def test_exact_relationship_remove_is_the_only_delete_shape_accepted() -> None:
    contract = ContractSpecV2.model_validate(
        _future_contract(
            effect="relationship_remove",
            method="DELETE",
            endpoint=(
                "/groups/{group_id}/members/{directory_object_id}/$ref"
            ),
        )
    )
    assert contract.effect is ContractEffect.RELATIONSHIP_REMOVE
    assert contract.graph.method == "DELETE"
    assert contract.graph.endpoint.endswith("/$ref")


def test_endpoint_placeholder_cannot_accept_an_unsafe_substitution() -> None:
    candidate = _future_contract(
        effect="relationship_remove",
        method="DELETE",
        endpoint="/groups/{group_id}/members/{directory_object_id}/$ref",
    )
    candidate["input_schema"]["properties"]["directory_object_id"] = {
        "type": "string"
    }
    with pytest.raises(
        ValidationError,
        match="endpoint placeholders require a safe path-segment schema",
    ):
        ContractSpecV2.model_validate(candidate)


@pytest.mark.parametrize(
    "endpoint",
    [
        "/groups/{group_id}/members/{directory_object_id}",
        "/groups/{group_id}/members/{directory_object_id}/$REF",
        "/groups/{group_id}/members/{directory_object_id}/%24ref",
        "/groups/{group_id}/members/{directory_object_id}/{suffix}",
        "/groups/{group_id}/members/{directory_object_id}/$ref/..",
        "/groups/{group_id}/members/../{directory_object_id}/$ref",
        "/groups/{group_id}/members/{directory_object_id}%2F$ref",
        "/groups/{group_id}/members/{directory_object_id}/$ref?force=true",
    ],
)
def test_relationship_remove_suffix_cannot_be_omitted_or_bypassed(
    endpoint: str,
) -> None:
    with pytest.raises(ValidationError):
        ContractSpecV2.model_validate(
            _future_contract(
                effect="relationship_remove",
                method="DELETE",
                endpoint=endpoint,
            )
        )


@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_relationship_remove_rejects_non_delete_methods(method: str) -> None:
    with pytest.raises(
        ValidationError,
        match="contract effect and Graph method are incompatible",
    ):
        ContractSpecV2.model_validate(
            _future_contract(
                effect="relationship_remove",
                method=method,
                endpoint=(
                    "/groups/{group_id}/members/"
                    "{directory_object_id}/$ref"
                ),
            )
        )


def test_delete_cannot_be_declared_as_another_effect() -> None:
    with pytest.raises(
        ValidationError,
        match="contract effect and Graph method are incompatible",
    ):
        ContractSpecV2.model_validate(
            _future_contract(
                effect="update_properties",
                method="DELETE",
                endpoint=(
                    "/groups/{group_id}/members/"
                    "{directory_object_id}/$ref"
                ),
            )
        )


@pytest.mark.parametrize(
    "field",
    [
        "api_version",
        "body",
        "endpoint",
        "graph_endpoint",
        "headers",
        "method",
        "query",
        "query_params",
        "request_body",
        "scope",
        "scopes",
        "suffix",
        "url",
    ],
)
def test_caller_cannot_supply_graph_request_components(field: str) -> None:
    with pytest.raises(
        ValidationError,
        match="caller-controlled Graph request fields",
    ):
        ContractSpecV2.model_validate(
            _future_contract(
                effect="relationship_remove",
                method="DELETE",
                endpoint=(
                    "/groups/{group_id}/members/"
                    "{directory_object_id}/$ref"
                ),
                extra_input_field=field,
            )
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "/beta/groups/{group_id}/members/{directory_object_id}/$ref",
        "/BETA/groups/{group_id}/members/{directory_object_id}/$ref",
        "/v1.0/../beta/groups/{group_id}/members/{directory_object_id}/$ref",
    ],
)
def test_graph_beta_and_path_traversal_are_rejected(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        ContractSpecV2.model_validate(
            _future_contract(
                effect="relationship_remove",
                method="DELETE",
                endpoint=endpoint,
            )
        )


def test_explicit_effect_contract_requires_graph_v1() -> None:
    candidate = _future_contract(
        effect="relationship_remove",
        method="DELETE",
        endpoint="/groups/{group_id}/members/{directory_object_id}/$ref",
    )
    candidate["graph"]["api_version"] = "beta"
    with pytest.raises(ValidationError, match="api_version"):
        ContractSpecV2.model_validate(candidate)


def test_effect_model_serialization_and_digest_are_deterministic() -> None:
    first = effect_model_document()
    reordered = {key: first[key] for key in reversed(list(first))}
    assert canonical_json(first) == canonical_json(reordered)
    assert effect_model_digest() == sha256_digest(reordered)
    assert first["effects"] == sorted(first["effects"])
    assert first["caller_controlled_graph_fields"] == sorted(
        first["caller_controlled_graph_fields"]
    )


def test_one_effect_rule_change_changes_the_digest() -> None:
    changed = copy.deepcopy(effect_model_document())
    changed["relationship_remove_suffix"] = "/unsafe"
    assert sha256_digest(changed) != effect_model_digest()


def test_signed_graph_and_playbook_surfaces_are_unchanged() -> None:
    contracts = load_global_manifest()
    playbooks = load_global_playbook_manifest(contracts)
    assert sha256_digest(contracts) == CONTRACT_MANIFEST_DIGEST
    assert sha256_digest(playbooks) == PLAYBOOK_MANIFEST_DIGEST
    assert [(item.graph.method, item.graph.endpoint) for item in contracts.contracts] == [
        ("GET", "/organization"),
        ("GET", "/users/{user_id}"),
        ("GET", "/identity/conditionalAccess/policies"),
        ("GET", "/roleManagement/directory/roleAssignments"),
        ("GET", "/identity/conditionalAccess/policies"),
        ("GET", "/oauth2PermissionGrants"),
        ("GET", "/oauth2PermissionGrants"),
        ("GET", "/applications/{application_id}"),
        ("PATCH", "/users/{user_id}"),
    ]


def test_public_effect_artifacts_contain_no_private_namespace_or_tenant_data() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "contract-artifacts/contract-effect-model.json",
        root / "src/m365_secure_mcp/release_data/contract-effect-model.json",
        root / "docs/SECURE_OPERATIONS.md",
    ]
    payload = "\n".join(path.read_text() for path in paths if path.exists())
    assert "werixo.internal" not in payload.lower()
    assert "11111111-1111-4111-8111-111111111111" not in payload
    assert "customer tenant" not in json.dumps(effect_model_document()).lower()
