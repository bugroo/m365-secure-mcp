from __future__ import annotations

import base64
import hashlib
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
    CORE_REQUIRED_SCENARIOS,
    EXTENDED_REQUIRED_SCENARIOS,
    LAB_ENABLE_ENV,
    LAB_INVENTORY_ENV,
    LAB_OPERATOR_PROFILE_ENV,
    LAB_PROFILE_ENV,
    LAB_TENANT_ENV,
    LAB_WRITE_ACK,
    LAB_WRITE_ACK_ENV,
    IdentityLiveLabInventory,
    LiveLabOperatorProfileName,
    LiveLabTokenContext,
    evaluate_live_lab_evidence,
    load_gate_from_environment,
    load_live_lab_inventory,
    main,
    public_requirements,
    scan_public_live_lab_evidence,
    validate_live_lab_gate,
    validate_live_lab_token_context,
)
from m365_secure_mcp.security import SecurityError

from .operator_helpers import authority_record, synthetic_governance

ROOT = Path(__file__).resolve().parents[1]


def _uuid(number: int) -> str:
    return str(UUID(int=number, version=4))


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _profile(
    name: str,
    subject_number: int,
    digest_character: str,
    roles: list[str],
    operations: list[str],
    *,
    approval_character: str | None,
) -> dict[str, object]:
    return {
        "profile_id": name,
        "subject_id": _uuid(subject_number),
        "governance_policy_digest": _digest(digest_character),
        "approval_public_key_sha256": (
            _digest(approval_character)
            if approval_character is not None
            else None
        ),
        "keyring_service": f"m365-secure-mcp-live-lab-{name}",
        "required_roles": roles,
        "allowed_operation_ids": operations,
    }


def _inventory_payload() -> dict[str, object]:
    users = {
        "normal_enabled_user_id": _uuid(10),
        "normal_disabled_user_id": _uuid(11),
        "direct_license_user_id": _uuid(12),
        "guest_user_id": _uuid(13),
        "administrator_user_id": _uuid(14),
        "break_glass_user_id": _uuid(15),
        "no_usage_location_user_id": _uuid(16),
        "outside_allowlist_user_id": _uuid(17),
    }
    groups = {
        "allowed_static_group_id": _uuid(30),
        "protected_static_group_id": _uuid(31),
        "outside_allowlist_group_id": _uuid(32),
    }
    allowed_sku = _uuid(40)
    allowed_plan = _uuid(50)
    return {
        "schema_version": "2.0",
        "environment": "dedicated-nonproduction",
        "profile": "live-lab",
        "tenant_id": _uuid(1),
        "client_id": _uuid(2),
        "authentication": {
            "application_type": "single-tenant-public-client",
            "primary_flow": "system-browser-pkce",
            "fallback_flow": "device-code-explicit",
            "redirect_uri": "http://localhost",
            "token_cache": "os-keychain-owner-only",
            "mfa_compatible": True,
            "client_secret_prohibited": True,
            "ropc_prohibited": True,
        },
        "operators": {
            "session": _profile(
                "session-operator",
                60,
                "a",
                ["Global Reader", "Helpdesk Administrator"],
                ["entra.user.sessions.revoke"],
                approval_character="1",
            ),
            "account": _profile(
                "account-operator",
                61,
                "b",
                ["Global Reader", "User Administrator"],
                ["entra.user.account_state.set"],
                approval_character="2",
            ),
            "group": _profile(
                "group-operator",
                62,
                "c",
                ["Global Reader", "Groups Administrator"],
                [
                    "entra.group.user_membership.add",
                    "entra.group.user_membership.remove",
                ],
                approval_character="3",
            ),
            "license": _profile(
                "license-operator",
                63,
                "d",
                ["Global Reader", "License Administrator"],
                ["entra.user.direct_license.set"],
                approval_character="4",
            ),
            "negative": _profile(
                "negative-operator",
                64,
                "e",
                ["Global Reader"],
                [],
                approval_character=None,
            ),
        },
        "candidate_manifest_digest": sha256_digest(load_identity_candidate(ROOT)),
        "effect_model_digest": effect_model_digest(),
        "marker": {
            "group_id": _uuid(4),
            "description_digest": _digest("f"),
        },
        "core_users": users,
        "core_groups": groups,
        "core_relationships": {
            "already_member_user_id": users["normal_enabled_user_id"],
            "already_member_group_id": groups["allowed_static_group_id"],
            "non_member_user_id": users["normal_disabled_user_id"],
            "non_member_group_id": groups["allowed_static_group_id"],
        },
        "extended": {"state": "not_provisioned"},
        "licenses": {
            "allowed_sku_id": allowed_sku,
            "disallowed_sku_id": _uuid(41),
            "allowed_service_plan_ids": [allowed_plan],
            "disallowed_service_plan_id": _uuid(51),
        },
        "allowlisted_user_ids": sorted(
            value
            for key, value in users.items()
            if key != "outside_allowlist_user_id"
        ),
        "allowlisted_group_ids": sorted(
            value
            for key, value in groups.items()
            if key != "outside_allowlist_group_id"
        ),
        "protected_user_ids": sorted(
            [users["administrator_user_id"], users["break_glass_user_id"]]
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


def _environment(path: Path, *, profile: str = "account-operator") -> dict[str, str]:
    payload = _inventory_payload()
    profile_document = payload["operators"][profile.split("-")[0]]  # type: ignore[index]
    return {
        LAB_ENABLE_ENV: "1",
        LAB_PROFILE_ENV: "live-lab",
        LAB_TENANT_ENV: str(payload["tenant_id"]),
        LAB_INVENTORY_ENV: str(path),
        LAB_OPERATOR_PROFILE_ENV: profile,
        LAB_WRITE_ACK_ENV: LAB_WRITE_ACK,
        "M365_CLIENT_ID": str(payload["client_id"]),
        "M365_TENANT_ID": str(payload["tenant_id"]),
        "M365_ALLOWED_USER_OBJECT_IDS": str(profile_document["subject_id"]),
        "M365_TOKEN_CACHE_MODE": "keyring",
        "M365_KEYRING_SERVICE": str(profile_document["keyring_service"]),
        "M365_GOVERNANCE_POLICY_PATH": "/external/governance.json",
        "M365_GOVERNANCE_PUBLIC_KEY_PATH": "/external/governance.pub",
        "M365_APPROVAL_PUBLIC_KEY_PATH": "/external/approval.pub",
    }


def _write_effect_profile_authority(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    profile: str,
) -> tuple[dict[str, object], dict[str, str]]:
    profile_key = profile.split("-")[0]
    profile_document = payload["operators"][profile_key]  # type: ignore[index]
    operation_ids = tuple(profile_document["allowed_operation_ids"])
    candidate = load_identity_candidate(ROOT)
    contracts = [
        contract for contract in candidate.contracts if contract.id in operation_ids
    ]
    approval_signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        f"{profile_key}-approver",
        f"{profile_key}-identity",
        f"{profile_key}-approval-key",
        f"{profile_key}-operations",
        approval_signer,
    )
    policies = [synthetic_governance(contract, (authority,))[0] for contract in contracts]
    policy_document = policies[0].model_dump(mode="json")
    candidate_digest = sha256_digest(candidate)
    policy_document["tenant_id"] = payload["tenant_id"]
    policy_document["contract_manifest_digest"] = candidate_digest
    policy_document["profiles"]["selected-write"]["enabled_contracts"] = list(
        operation_ids
    )
    policy_document["resources"] = {
        "tenants": [payload["tenant_id"]],
        "users": payload["allowlisted_user_ids"],
        "groups": payload["allowlisted_group_ids"],
        "applications": [],
        "service_principals": [],
        "protected_user_ids": payload["protected_user_ids"],
        "break_glass_user_ids": [
            payload["core_users"]["break_glass_user_id"],  # type: ignore[index]
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
    approval_raw = approval_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    profile_document["governance_policy_digest"] = sha256_digest(policy)
    profile_document["approval_public_key_sha256"] = (
        f"sha256:{hashlib.sha256(approval_raw).hexdigest()}"
    )

    private_root = tmp_path / "external-authority"
    private_root.mkdir(mode=0o700)
    governance_signer = Ed25519PrivateKey.generate()
    bundle = sign_governance_policy(
        policy,
        governance_signer,
        key_id=f"{profile_key}-governance-key",
    )
    policy_path = private_root / "governance.signed.json"
    policy_path.write_text(json.dumps(bundle.model_dump(mode="json"), sort_keys=True))
    policy_path.chmod(0o600)
    governance_key_path = private_root / "governance.pub"
    governance_key_path.write_text(public_key_text(governance_signer))
    governance_key_path.chmod(0o600)
    approval_key_path = private_root / "approval.pub"
    approval_key_path.write_text(base64.b64encode(approval_raw).decode("ascii"))
    approval_key_path.chmod(0o600)
    return payload, {
        "M365_GOVERNANCE_POLICY_PATH": str(policy_path),
        "M365_GOVERNANCE_PUBLIC_KEY_PATH": str(governance_key_path),
        "M365_APPROVAL_PUBLIC_KEY_PATH": str(approval_key_path),
    }


def test_inventory_schema_enforces_isolated_profiles_and_exact_topology(
    tmp_path: Path,
) -> None:
    inventory = _write_inventory(tmp_path / "inventory.json")
    assert inventory.schema_version == "2.0"
    assert len(
        {
            inventory.operators.session.subject_id,
            inventory.operators.account.subject_id,
            inventory.operators.group.subject_id,
            inventory.operators.license.subject_id,
            inventory.operators.negative.subject_id,
        }
    ) == 5
    assert inventory.operators.negative.allowed_operation_ids == ()

    changed = _inventory_payload()
    changed["operators"]["negative"]["subject_id"] = changed["operators"]["account"][  # type: ignore[index]
        "subject_id"
    ]
    with pytest.raises(ValidationError, match="subjects must be distinct"):
        IdentityLiveLabInventory.model_validate(changed)


def test_extended_inventory_is_explicitly_not_provisioned_or_exact() -> None:
    inventory = IdentityLiveLabInventory.model_validate(_inventory_payload())
    assert inventory.extended.state == "not_provisioned"

    changed = _inventory_payload()
    changed["extended"] = {
        "state": "provisioned",
        "users": {
            "synchronized_user_id": _uuid(70),
            "pim_active_user_id": _uuid(71),
            "pim_eligible_user_id": _uuid(72),
            "inherited_license_user_id": _uuid(73),
        },
        "groups": {
            "dynamic_group_id": _uuid(74),
            "role_assignable_group_id": _uuid(75),
            "inherited_license_group_id": _uuid(76),
        },
        "relationships": {
            "inherited_license_user_id": _uuid(73),
            "inherited_license_group_id": _uuid(76),
        },
    }
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
        ("M365_TENANT_ID", _uuid(99), "does not match"),
        ("M365_TOKEN_CACHE_MODE", "memory", "owner-only"),
        ("M365_AUTH_FLOW", "password", "prohibited"),
    ],
)
def test_gate_fails_closed_on_process_and_auth_bindings(
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
    inventory = _write_inventory(tmp_path / "inventory.json")
    environment = _environment(tmp_path / "inventory.json")
    environment[key] = value
    with pytest.raises(SecurityError, match=message):
        validate_live_lab_gate(inventory, root=ROOT, environ=environment)


@pytest.mark.parametrize("forbidden", ["M365_CLIENT_SECRET", "M365_USERNAME", "M365_PASSWORD"])
def test_gate_rejects_confidential_client_and_ropc_material(
    tmp_path: Path,
    forbidden: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        live_lab_module,
        "_validate_external_authority",
        lambda *_args, **_kwargs: None,
    )
    inventory = _write_inventory(tmp_path / "inventory.json")
    environment = _environment(tmp_path / "inventory.json")
    environment[forbidden] = "never-accepted"
    with pytest.raises(SecurityError, match="ROPC"):
        validate_live_lab_gate(inventory, root=ROOT, environ=environment)


def test_gate_accepts_exact_profile_and_emits_no_identifiers(
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
    result = load_gate_from_environment(root=ROOT, environ=_environment(path))
    serialized = result.model_dump_json()
    assert result.operator_profile is LiveLabOperatorProfileName.ACCOUNT
    assert result.auth_flow == "system-browser-pkce"
    assert result.core_gate == "required"
    assert result.extended_gate == "not_provisioned"
    assert str(inventory.tenant_id) not in serialized
    assert str(inventory.client_id) not in serialized


def test_gate_accepts_only_explicit_device_code_fallback(
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
    environment["M365_AUTH_FLOW"] = "device_code"
    with pytest.raises(SecurityError, match="prohibited"):
        validate_live_lab_gate(inventory, root=ROOT, environ=environment)
    environment["M365_ALLOW_DEVICE_CODE"] = "true"
    result = validate_live_lab_gate(inventory, root=ROOT, environ=environment)
    assert result.auth_flow == "device-code-explicit"


def test_external_boundary_requires_one_exact_operator_allowlist(
    tmp_path: Path,
) -> None:
    inventory = IdentityLiveLabInventory.model_validate(_inventory_payload())
    environment = _environment(tmp_path / "inventory.json")
    environment["M365_ALLOWED_USER_OBJECT_IDS"] = ",".join(
        [
            str(inventory.operators.account.subject_id),
            str(inventory.operators.session.subject_id),
        ]
    )
    with pytest.raises(SecurityError, match="profile-exact"):
        live_lab_module._validate_external_authority(
            inventory,
            root=ROOT,
            environ=environment,
        )


def test_gate_verifies_profile_specific_governance_and_approval(
    tmp_path: Path,
) -> None:
    path = tmp_path / "inventory.json"
    payload, authority_environment = _write_effect_profile_authority(
        tmp_path,
        _inventory_payload(),
        profile="group-operator",
    )
    _write_inventory(path, payload)
    environment = _environment(path, profile="group-operator")
    environment.update(authority_environment)
    result = load_gate_from_environment(root=ROOT, environ=environment)
    assert result.operator_profile is LiveLabOperatorProfileName.GROUP

    unrelated = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    approval_path = Path(environment["M365_APPROVAL_PUBLIC_KEY_PATH"])
    approval_path.write_text(base64.b64encode(unrelated).decode("ascii"))
    approval_path.chmod(0o600)
    with pytest.raises(SecurityError, match="not governed"):
        load_gate_from_environment(root=ROOT, environ=environment)


def _token_context(
    inventory: IdentityLiveLabInventory,
    *,
    profile: LiveLabOperatorProfileName = LiveLabOperatorProfileName.ACCOUNT,
) -> LiveLabTokenContext:
    operator = inventory.operators.get(profile)
    plan_digest = _digest("9")
    return LiveLabTokenContext(
        tenant_id=inventory.tenant_id,
        client_id=inventory.client_id,
        subject_id=operator.subject_id,
        operator_profile=profile,
        authority=f"https://login.microsoftonline.com/{inventory.tenant_id}",
        auth_flow="system-browser-pkce",
        keyring_service=operator.keyring_service,
        delegated_scopes=tuple(sorted(live_lab_module.REQUIRED_DELEGATED_SCOPES)),
        directory_roles=tuple(sorted(operator.required_roles)),
        plan_digest=plan_digest,
        approval_plan_digest=plan_digest,
        approval_tenant_id=inventory.tenant_id,
        approval_subject_id=operator.subject_id,
        approval_profile="selected-write",
        policy_digest=operator.governance_policy_digest,
        operation_id=(
            operator.allowed_operation_ids[0]
            if operator.allowed_operation_ids
            else "none"
        ),
    )


def test_token_context_binds_tenant_subject_profile_approval_and_plan() -> None:
    inventory = IdentityLiveLabInventory.model_validate(_inventory_payload())
    validate_live_lab_token_context(inventory, _token_context(inventory))

    for field, value in (
        ("subject_id", inventory.operators.session.subject_id),
        ("policy_digest", inventory.operators.session.governance_policy_digest),
        ("approval_plan_digest", _digest("8")),
        ("approval_tenant_id", UUID(_uuid(99))),
    ):
        changed = _token_context(inventory).model_copy(update={field: value})
        with pytest.raises(SecurityError):
            validate_live_lab_token_context(inventory, changed)


def test_wrong_profile_or_missing_effect_or_evidence_role_fails_closed() -> None:
    inventory = IdentityLiveLabInventory.model_validate(_inventory_payload())
    context = _token_context(inventory)
    missing_effect = context.model_copy(
        update={"directory_roles": ("Global Reader",)}
    )
    with pytest.raises(SecurityError, match="role evidence"):
        validate_live_lab_token_context(inventory, missing_effect)
    missing_evidence = context.model_copy(
        update={"directory_roles": ("User Administrator",)}
    )
    with pytest.raises(SecurityError, match="role evidence"):
        validate_live_lab_token_context(inventory, missing_evidence)
    negative = _token_context(
        inventory,
        profile=LiveLabOperatorProfileName.NEGATIVE,
    )
    with pytest.raises(SecurityError, match="no effect authority"):
        validate_live_lab_token_context(inventory, negative)


def _public_evidence(
    *,
    core_state: str = "passed",
    extended_state: str = "not_executed",
) -> dict[str, object]:
    cases: list[dict[str, object]] = []
    for level, scenarios, state in (
        ("core", CORE_REQUIRED_SCENARIOS, core_state),
        ("extended", EXTENDED_REQUIRED_SCENARIOS, extended_state),
    ):
        for scenario in scenarios:
            cases.append(
                {
                    "lab_level": level,
                    "scenario": scenario,
                    "resource_type": "user",
                    "operation_id": "entra.user.account_state.set",
                    "expected_status": "EXECUTED_VERIFIED",
                    "observed_status": (
                        "NOT_EXECUTED" if state == "not_executed" else "EXECUTED_VERIFIED"
                    ),
                    "approximate_duration": "1_to_5s",
                    "classification": "verified" if state == "passed" else "blocked",
                    "error_code": None,
                    "contract_digest": _digest("6"),
                    "execution_state": state,
                }
            )
    return {
        "schema_version": "2.0",
        "evidence_kind": "sanitized-identity-live-lab",
        "contains_customer_data": False,
        "candidate_manifest_digest": sha256_digest(load_identity_candidate(ROOT)),
        "cases": sorted(cases, key=lambda item: str(item["scenario"])),
    }


def test_core_is_required_for_preview_and_extended_for_stable() -> None:
    evidence = scan_public_live_lab_evidence(_public_evidence())
    eligibility = evaluate_live_lab_evidence(evidence)
    assert eligibility.preview_signing_eligible is True
    assert eligibility.stable_promotion_eligible is False
    assert set(eligibility.extended_not_executed) == set(EXTENDED_REQUIRED_SCENARIOS)

    not_run = scan_public_live_lab_evidence(
        _public_evidence(core_state="not_executed")
    )
    assert evaluate_live_lab_evidence(not_run).preview_signing_eligible is False
    complete = scan_public_live_lab_evidence(
        _public_evidence(extended_state="passed")
    )
    assert evaluate_live_lab_evidence(complete).stable_promotion_eligible is True


def test_public_evidence_requires_complete_core_and_extended_coverage() -> None:
    payload = _public_evidence()
    payload["cases"] = payload["cases"][:-1]  # type: ignore[index]
    with pytest.raises(SecurityError, match="schema"):
        scan_public_live_lab_evidence(payload)


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
def test_public_evidence_rejects_identifiers_and_secrets(
    key: str,
    value: str,
) -> None:
    payload = _public_evidence()
    payload[key] = value
    with pytest.raises(SecurityError):
        scan_public_live_lab_evidence(payload)


def test_public_requirements_are_neutral_and_complete() -> None:
    requirements = public_requirements()
    serialized = json.dumps(requirements)
    assert requirements["resource_counts"]["operator_profiles"] == 5  # type: ignore[index]
    assert requirements["authentication"]["primary_flow"] == "system-browser-pkce"  # type: ignore[index]
    assert requirements["authentication"]["redirect_uri"] == "http://localhost"  # type: ignore[index]
    assert "RoleManagement.Read.Directory" in serialized
    assert "Groups Administrator" in serialized
    assert "negative-operator" in serialized
    assert not re_uuid_search(serialized)


def test_committed_inventory_template_contains_placeholders_only() -> None:
    template_path = ROOT / "examples/identity-live-lab.inventory.template.json"
    raw = template_path.read_text()
    payload = json.loads(raw)
    assert "${LAB_TENANT_OBJECT_ID}" in raw
    assert not re_uuid_search(raw)
    assert "@" not in raw
    assert payload["schema_version"] == "2.0"
    assert payload["extended"]["state"] == "not_provisioned"
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


def test_cli_failure_is_redacted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "private-inventory.json"
    assert main(["validate-inventory", "--inventory", str(path)]) == 2
    captured = capsys.readouterr()
    assert str(path) not in captured.err
    assert "IDENTITY_LIVE_LAB_GATE_FAILED" in captured.err
