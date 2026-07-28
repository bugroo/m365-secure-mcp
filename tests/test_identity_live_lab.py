from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import m365_secure_mcp.identity_live_lab as live_lab_module
from m365_secure_mcp.contract_compiler import load_identity_candidate
from m365_secure_mcp.contract_manifest import effect_model_digest, sha256_digest
from m365_secure_mcp.governance import (
    GovernancePolicyV3,
    public_key_text,
    sign_governance_policy,
)
from m365_secure_mcp.identity_live_lab import (
    LAB_ENABLE_ENV,
    LAB_INVENTORY_ENV,
    LAB_PROFILE_ENV,
    LAB_TENANT_ENV,
    LAB_WRITE_ACK,
    LAB_WRITE_ACK_ENV,
    IdentityLiveLabInventory,
    load_gate_from_environment,
    load_live_lab_inventory,
    main,
    public_requirements,
    scan_public_live_lab_evidence,
    validate_live_lab_gate,
)
from m365_secure_mcp.security import SecurityError

from .operator_helpers import authority_record, synthetic_governance

ROOT = Path(__file__).resolve().parents[1]


def _uuid(number: int) -> str:
    return str(UUID(int=number, version=4))


def _inventory_payload(
    *,
    governance_policy_digest: str = "sha256:" + ("a" * 64),
) -> dict[str, object]:
    users = {
        "normal_enabled_user_id": _uuid(10),
        "normal_disabled_user_id": _uuid(11),
        "direct_license_user_id": _uuid(12),
        "inherited_license_user_id": _uuid(13),
        "guest_user_id": _uuid(14),
        "synchronized_user_id": _uuid(15),
        "administrator_user_id": _uuid(16),
        "break_glass_user_id": _uuid(17),
        "no_usage_location_user_id": _uuid(18),
        "outside_allowlist_user_id": _uuid(19),
    }
    groups = {
        "allowed_static_group_id": _uuid(30),
        "protected_static_group_id": _uuid(31),
        "dynamic_group_id": _uuid(32),
        "role_assignable_group_id": _uuid(33),
        "outside_allowlist_group_id": _uuid(34),
    }
    allowed_users = sorted(
        value
        for key, value in users.items()
        if key != "outside_allowlist_user_id"
    )
    allowed_groups = sorted(
        value
        for key, value in groups.items()
        if key != "outside_allowlist_group_id"
    )
    allowed_plan = _uuid(50)
    allowed_sku = _uuid(40)
    return {
        "schema_version": "1.0",
        "environment": "dedicated-nonproduction",
        "profile": "live-lab",
        "tenant_id": _uuid(1),
        "client_id": _uuid(2),
        "operator_object_id": _uuid(3),
        "candidate_manifest_digest": sha256_digest(load_identity_candidate(ROOT)),
        "effect_model_digest": effect_model_digest(),
        "governance_policy_digest": governance_policy_digest,
        "marker": {
            "group_id": _uuid(4),
            "description_digest": "sha256:" + ("b" * 64),
        },
        "users": users,
        "groups": groups,
        "relationships": {
            "already_member_user_id": users["normal_enabled_user_id"],
            "already_member_group_id": groups["allowed_static_group_id"],
            "non_member_user_id": users["normal_disabled_user_id"],
            "non_member_group_id": groups["allowed_static_group_id"],
            "inherited_license_group_id": groups["allowed_static_group_id"],
        },
        "licenses": {
            "allowed_sku_id": allowed_sku,
            "disallowed_sku_id": _uuid(41),
            "allowed_service_plan_ids": [allowed_plan],
            "disallowed_service_plan_id": _uuid(51),
        },
        "allowlisted_user_ids": allowed_users,
        "allowlisted_group_ids": allowed_groups,
        "protected_user_ids": sorted(
            [
                users["administrator_user_id"],
                users["break_glass_user_id"],
            ]
        ),
        "protected_group_ids": [groups["protected_static_group_id"]],
        "allowed_sku_ids": [allowed_sku],
        "allowed_service_plan_ids": {allowed_sku: [allowed_plan]},
    }


def _write_inventory(
    path: Path,
    payload: dict[str, object] | None = None,
) -> IdentityLiveLabInventory:
    path.write_text(json.dumps(payload or _inventory_payload()))
    path.chmod(0o600)
    return load_live_lab_inventory(path)


def _environment(path: Path) -> dict[str, str]:
    payload = _inventory_payload()
    return {
        LAB_ENABLE_ENV: "1",
        LAB_PROFILE_ENV: "live-lab",
        LAB_TENANT_ENV: str(payload["tenant_id"]),
        LAB_INVENTORY_ENV: str(path),
        LAB_WRITE_ACK_ENV: LAB_WRITE_ACK,
        "M365_CLIENT_ID": str(payload["client_id"]),
        "M365_GOVERNANCE_POLICY_PATH": "/external/governance.json",
        "M365_GOVERNANCE_PUBLIC_KEY_PATH": "/external/governance.pub",
        "M365_APPROVAL_PUBLIC_KEY_PATH": "/external/approval.pub",
    }


def _write_external_authority(
    tmp_path: Path,
    payload: dict[str, object],
) -> tuple[dict[str, object], dict[str, str]]:
    candidate = load_identity_candidate(ROOT)
    approval_signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "lab-approver",
        "lab-operator",
        "lab-approval-key",
        "lab-operations",
        approval_signer,
    )
    policies = [
        synthetic_governance(contract, (authority,))[0]
        for contract in candidate.contracts
    ]
    policy_document = policies[0].model_dump(mode="json")
    candidate_digest = sha256_digest(candidate)
    policy_document["tenant_id"] = payload["tenant_id"]
    policy_document["contract_manifest_digest"] = candidate_digest
    policy_document["profiles"]["selected-write"]["enabled_contracts"] = sorted(
        contract.id for contract in candidate.contracts
    )
    policy_document["resources"] = {
        "tenants": [payload["tenant_id"]],
        "users": payload["allowlisted_user_ids"],
        "groups": payload["allowlisted_group_ids"],
        "applications": [],
        "service_principals": [],
        "protected_user_ids": payload["protected_user_ids"],
        "break_glass_user_ids": [
            payload["users"]["break_glass_user_id"],
        ],
        "emergency_access_user_ids": [],
        "protected_group_ids": payload["protected_group_ids"],
        "allowed_sku_ids": payload["allowed_sku_ids"],
        "allowed_service_plan_ids": payload["allowed_service_plan_ids"],
        "synchronized_user_policy": "reject",
    }
    policy_document["operations"]["contract_manifest_digest"] = candidate_digest
    policy_document["operations"]["operations"] = sorted(
        [
            policy.operations.operations[0].model_dump(mode="json")
            for policy in policies
        ],
        key=lambda value: value["operation_id"],
    )
    policy = GovernancePolicyV3.model_validate(policy_document)
    payload = {
        **payload,
        "governance_policy_digest": sha256_digest(policy),
    }

    private_root = tmp_path / "external-authority"
    private_root.mkdir(mode=0o700)
    private_root.chmod(0o700)
    governance_signer = Ed25519PrivateKey.generate()
    bundle = sign_governance_policy(
        policy,
        governance_signer,
        key_id="lab-governance-key",
    )
    policy_path = private_root / "governance.signed.json"
    policy_path.write_text(
        json.dumps(bundle.model_dump(mode="json"), sort_keys=True)
    )
    policy_path.chmod(0o600)
    governance_key_path = private_root / "governance.pub"
    governance_key_path.write_text(public_key_text(governance_signer))
    governance_key_path.chmod(0o600)
    approval_key_path = private_root / "approval.pub"
    approval_raw = approval_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    approval_key_path.write_text(base64.b64encode(approval_raw).decode("ascii"))
    approval_key_path.chmod(0o600)
    return payload, {
        "M365_GOVERNANCE_POLICY_PATH": str(policy_path),
        "M365_GOVERNANCE_PUBLIC_KEY_PATH": str(governance_key_path),
        "M365_APPROVAL_PUBLIC_KEY_PATH": str(approval_key_path),
    }


def test_inventory_schema_enforces_exact_fixture_topology(tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    inventory = _write_inventory(path)
    assert inventory.profile == "live-lab"
    assert inventory.environment == "dedicated-nonproduction"

    changed = _inventory_payload()
    changed["allowlisted_user_ids"] = [
        *changed["allowlisted_user_ids"],  # type: ignore[index]
        changed["users"]["outside_allowlist_user_id"],  # type: ignore[index]
    ]
    with pytest.raises(ValidationError, match="allowlist"):
        IdentityLiveLabInventory.model_validate(changed)


def test_inventory_loader_rejects_symlink_and_non_owner_only_mode(
    tmp_path: Path,
) -> None:
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path)
    inventory_path.chmod(0o644)
    with pytest.raises(SecurityError, match="0600"):
        load_live_lab_inventory(inventory_path)

    inventory_path.chmod(0o600)
    symlink_path = tmp_path / "inventory-link.json"
    symlink_path.symlink_to(inventory_path)
    with pytest.raises(SecurityError, match="non-symlink"):
        load_live_lab_inventory(symlink_path)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        (LAB_ENABLE_ENV, "0", "explicitly enabled"),
        (LAB_PROFILE_ENV, "selected-write", "live-lab profile"),
        (LAB_WRITE_ACK_ENV, "yes", "acknowledgement"),
        (LAB_TENANT_ENV, _uuid(99), "does not match"),
    ],
)
def test_gate_fails_closed_on_every_process_binding(
    tmp_path: Path,
    key: str,
    value: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        live_lab_module,
        "_validate_external_authority",
        lambda *_args, **_kwargs: None,
    )
    path = tmp_path / "inventory.json"
    inventory = _write_inventory(path)
    environment = _environment(path)
    environment[key] = value
    with pytest.raises(SecurityError, match=message):
        validate_live_lab_gate(inventory, root=ROOT, environ=environment)


def test_gate_requires_external_authority_paths_without_exposing_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        live_lab_module,
        "_validate_external_authority",
        lambda *_args, **_kwargs: None,
    )
    path = tmp_path / "inventory.json"
    inventory = _write_inventory(path)
    environment = _environment(path)
    environment.pop("M365_APPROVAL_PUBLIC_KEY_PATH")
    with pytest.raises(SecurityError) as caught:
        validate_live_lab_gate(inventory, root=ROOT, environ=environment)
    message = str(caught.value)
    assert str(path) not in message
    assert str(inventory.tenant_id) not in message
    assert "APPROVAL_PUBLIC_KEY" not in message


def test_gate_accepts_exact_external_inventory_and_emits_only_counts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "inventory.json"
    payload, authority_environment = _write_external_authority(
        tmp_path,
        _inventory_payload(),
    )
    _write_inventory(path, payload)
    environment = _environment(path)
    environment.update(authority_environment)
    result = load_gate_from_environment(root=ROOT, environ=environment)
    serialized = result.model_dump_json()
    assert result.status == "ready"
    assert result.resource_counts["users"] == 10
    assert "tenant_id" not in serialized
    assert _uuid(1) not in serialized
    assert _uuid(2) not in serialized


def test_gate_rejects_unbound_approval_verifier_without_private_leakage(
    tmp_path: Path,
) -> None:
    path = tmp_path / "inventory.json"
    payload, authority_environment = _write_external_authority(
        tmp_path,
        _inventory_payload(),
    )
    _write_inventory(path, payload)
    unrelated = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    approval_path = Path(authority_environment["M365_APPROVAL_PUBLIC_KEY_PATH"])
    approval_path.write_text(base64.b64encode(unrelated).decode("ascii"))
    approval_path.chmod(0o600)
    environment = _environment(path)
    environment.update(authority_environment)
    with pytest.raises(SecurityError, match="not governed") as caught:
        load_gate_from_environment(root=ROOT, environ=environment)
    assert str(payload["tenant_id"]) not in str(caught.value)


def test_public_requirements_are_tenant_neutral_and_complete() -> None:
    requirements = public_requirements()
    serialized = json.dumps(requirements)
    assert requirements["resource_counts"] == {
        "users": 10,
        "groups": 5,
        "independent_marker_groups": 1,
        "subscribed_skus": 2,
        "service_plan_classes": 2,
    }
    assert requirements["automatic_provisioning"] is False
    assert requirements["contains_identifiers"] is False
    assert "RoleManagement.Read.Directory" in serialized
    assert "Groups Administrator" in serialized
    assert not re_uuid_search(serialized)


def test_committed_inventory_template_contains_placeholders_only() -> None:
    template_path = (
        ROOT / "examples/identity-live-lab.inventory.template.json"
    )
    raw = template_path.read_text()
    payload = json.loads(raw)
    assert "${LAB_TENANT_OBJECT_ID}" in raw
    assert not re_uuid_search(raw)
    assert "@" not in raw
    assert (
        payload["candidate_manifest_digest"]
        == sha256_digest(load_identity_candidate(ROOT))
    )
    with pytest.raises(ValidationError):
        IdentityLiveLabInventory.model_validate(payload)


def re_uuid_search(value: str) -> bool:
    return bool(
        re.search(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}\b",
            value,
            re.IGNORECASE,
        )
    )


def _public_evidence() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "evidence_kind": "sanitized-identity-live-lab",
        "contains_customer_data": False,
        "candidate_manifest_digest": sha256_digest(load_identity_candidate(ROOT)),
        "cases": [
            {
                "scenario": "account.disable.normal",
                "resource_type": "user",
                "operation_id": "entra.user.account_state.set",
                "expected_status": "EXECUTED_VERIFIED",
                "observed_status": "EXECUTED_VERIFIED",
                "approximate_duration": "1_to_5s",
                "classification": "verified",
                "error_code": None,
                "contract_digest": "sha256:" + ("c" * 64),
                "passed": True,
            }
        ],
    }


def test_public_evidence_scanner_accepts_only_minimized_schema() -> None:
    evidence = scan_public_live_lab_evidence(_public_evidence())
    assert evidence.contains_customer_data is False
    assert evidence.cases[0].classification == "verified"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("tenant_id", _uuid(90)),
        ("upn", "lab-user@example.test"),
        ("ip_address", "192.0.2.10"),
        ("request_id", _uuid(91)),
        ("token", "eyJabcdefghijk.abcdefghijk.abcdefghijk"),
    ],
)
def test_public_evidence_scanner_rejects_identifiers_and_secrets(
    key: str,
    value: str,
) -> None:
    payload = _public_evidence()
    payload[key] = value
    with pytest.raises(SecurityError):
        scan_public_live_lab_evidence(payload)


def test_cli_failure_is_redacted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "private-inventory.json"
    assert main(["validate-inventory", "--inventory", str(path)]) == 2
    captured = capsys.readouterr()
    assert str(path) not in captured.err
    assert "IDENTITY_LIVE_LAB_GATE_FAILED" in captured.err
