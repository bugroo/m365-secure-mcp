from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import m365_secure_mcp.server as server_module
from m365_secure_mcp.config import Settings
from m365_secure_mcp.contract_compiler import load_identity_candidate
from m365_secure_mcp.contract_manifest import (
    AsyncBehavior,
    AuthorizationMode,
    RiskTier,
    canonical_json,
    effect_model_digest,
    sha256_digest,
)
from m365_secure_mcp.governance import (
    AsyncRequirement,
    GovernancePolicyV3,
    GovernanceProfile,
    GovernanceProfileName,
    GovernanceResources,
    OperationGovernanceBinding,
    OperationsGovernance,
    ProtectedObjectPolicy,
    ResourceFenceType,
)
from m365_secure_mcp.operator_authority import ApprovalTrustRegistry

from .operator_helpers import NOW, TENANT_ID, USER_ID, authority_binding, authority_record

GROUP_ID = UUID("44444444-4444-4444-8444-444444444444")
SKU_ID = UUID("55555555-5555-4555-8555-555555555555")
PLAN_ID = UUID("66666666-6666-4666-8666-666666666666")
ROOT = Path(__file__).resolve().parents[1]


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _write_private(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value))
    path.chmod(0o600)


def _policy(
    manifest,
    authority,
    *,
    enabled_contracts: list[str] | None = None,
) -> GovernancePolicyV3:
    binding = authority_binding(authority)
    operations = []
    for contract in manifest.contracts:
        if enabled_contracts is not None and contract.id not in enabled_contracts:
            continue
        operations.append(
            OperationGovernanceBinding(
                operation_id=contract.id,
                contract_id=contract.id,
                contract_digest=sha256_digest(contract),
                effect=contract.effect,
                minimum_risk_tier=RiskTier.T2,
                authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
                resource_fence_types=(
                    [ResourceFenceType.TENANT, ResourceFenceType.USER]
                    if "membership" not in contract.id
                    else [
                        ResourceFenceType.GROUP,
                        ResourceFenceType.TENANT,
                        ResourceFenceType.USER,
                    ]
                ),
                protected_object_policy=ProtectedObjectPolicy.EXCLUDE_PROTECTED,
                async_requirement=(
                    AsyncRequirement.PROVIDER_ASYNC_ALLOWED
                    if contract.async_behavior is AsyncBehavior.PROVIDER_EVENTUAL
                    else AsyncRequirement.SYNCHRONOUS_ONLY
                ),
                verification=contract.verification,
                resource_fence_id=contract.resource_fence_id,
                protected_object_policy_id=contract.protected_object_policy_id,
                verification_contract_id=contract.verification_contract_id,
                async_behavior=contract.async_behavior,
                approval_authority_ids=[binding.authority_id],
                required_signer_groups=[binding.signer_group],
            )
        )
    profiles = {
        GovernanceProfileName.ROUTINE_READ: GovernanceProfile(),
        GovernanceProfileName.ROUTINE_WRITE: GovernanceProfile(),
        GovernanceProfileName.PRIVILEGED_READ: GovernanceProfile(),
        GovernanceProfileName.SELECTED_WRITE: GovernanceProfile(
            enabled_contracts=(
                sorted(contract.id for contract in manifest.contracts)
                if enabled_contracts is None
                else sorted(enabled_contracts)
            )
        ),
        GovernanceProfileName.BREAK_GLASS: GovernanceProfile(
            break_glass_ttl_seconds=900
        ),
    }
    digest = sha256_digest(manifest)
    return GovernancePolicyV3(
        tenant_id=TENANT_ID,
        active_profile=GovernanceProfileName.SELECTED_WRITE,
        profiles=profiles,
        resources=GovernanceResources(
            tenants=[TENANT_ID],
            users=[USER_ID],
            groups=[GROUP_ID],
            allowed_sku_ids=[SKU_ID],
            allowed_service_plan_ids={SKU_ID: [PLAN_ID]},
        ),
        contract_manifest_digest=digest,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
        operations=OperationsGovernance(
            contract_manifest_digest=digest,
            contract_manifest_schema_versions=["2.0"],
            effect_model_schema_version="1.0",
            effect_model_digest=effect_model_digest(),
            approval_authorities=[binding],
            operations=sorted(operations, key=lambda item: item.operation_id),
        ),
    )


def test_active_signed_manifest_registers_only_five_fixed_identity_tools(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _private_root(tmp_path)
    manifest = load_identity_candidate(ROOT)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "identity-approver",
        "identity-person",
        "identity-key-2026",
        "identity-operations",
        signer,
    )
    trust_path = root / "trust.json"
    _write_private(
        trust_path,
        ApprovalTrustRegistry(authorities=(authority,)).model_dump(mode="json"),
    )
    policy = _policy(manifest, authority)
    monkeypatch.setattr(
        server_module,
        "load_active_identity_manifest",
        lambda: manifest,
    )
    monkeypatch.setattr(
        server_module,
        "load_verified_governance_policy",
        lambda *_: SimpleNamespace(policy=policy),
    )
    settings = Settings(
        tenant_id=str(TENANT_ID),
        client_id="99999999-9999-4999-8999-999999999999",
        profile="write",
        modules="profile",
        write_enabled=True,
        identity_operations_enabled=True,
        token_cache_mode="memory",  # noqa: S106
        allowed_user_object_ids=str(USER_ID),
        governance_policy_path=root / "governance.json",
        governance_public_key_path=root / "governance.pub",
        operator_approval_dir=root / "approvals",
        operator_approval_trust_path=trust_path,
        audit_log_path=root / "audit.jsonl",
        idempotency_db_path=root / "idempotency.sqlite3",
        recovery_capsule_path=root / "capsules.jsonl",
        operator_replay_db_path=root / "replay.sqlite3",
        operator_lifecycle_db_path=root / "lifecycle.sqlite3",
    )
    server = server_module.create_server(settings)
    names = {tool.name for tool in server._tool_manager.list_tools()}
    assert {
        "m365_entra_user_sessions_revoke",
        "m365_entra_user_account_state_set",
        "m365_entra_group_user_membership_add",
        "m365_entra_group_user_membership_remove",
        "m365_entra_user_direct_license_set",
    }.issubset(names)
    identity_tools = [
        tool
        for tool in server._tool_manager.list_tools()
        if tool.name.startswith("m365_entra_")
    ]
    assert len(identity_tools) == 5
    for tool in identity_tools:
        schema = json.dumps(tool.parameters)
        for forbidden in (
            '"api_version"',
            '"body"',
            '"headers"',
            '"method"',
            '"operation_id"',
            '"query"',
            '"scope"',
            '"tenant_id"',
            '"url"',
        ):
            assert forbidden not in schema
        assert tool.meta is not None
        assert tool.meta["m365_secure_mcp"]["maturity"] == "preview"


def test_legacy_equivalent_cannot_coexist_with_compiled_identity_effect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _private_root(tmp_path)
    manifest = load_identity_candidate(ROOT)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "identity-approver",
        "identity-person",
        "identity-key-2026",
        "identity-operations",
        signer,
    )
    trust_path = root / "trust.json"
    _write_private(
        trust_path,
        ApprovalTrustRegistry(authorities=(authority,)).model_dump(mode="json"),
    )
    policy = _policy(manifest, authority)
    monkeypatch.setattr(server_module, "load_active_identity_manifest", lambda: manifest)
    monkeypatch.setattr(
        server_module,
        "load_verified_governance_policy",
        lambda *_: SimpleNamespace(policy=policy),
    )
    settings = Settings(
        tenant_id=str(TENANT_ID),
        client_id="99999999-9999-4999-8999-999999999999",
        profile="write",
        modules="profile",
        write_enabled=True,
        identity_operations_enabled=True,
        write_actions="users.set_account_enabled",
        privileged_writes_enabled=True,
        allowed_target_user_ids=str(USER_ID),
        token_cache_mode="memory",  # noqa: S106
        governance_policy_path=root / "governance.json",
        governance_public_key_path=root / "governance.pub",
        operator_approval_dir=root / "approvals",
        operator_approval_trust_path=trust_path,
    )
    with pytest.raises(ValueError, match="cannot be enabled together"):
        server_module.create_server(settings)


def test_signed_governance_limits_the_exposed_identity_contracts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _private_root(tmp_path)
    manifest = load_identity_candidate(ROOT)
    signer = Ed25519PrivateKey.generate()
    authority = authority_record(
        "identity-approver",
        "identity-person",
        "identity-key-2026",
        "identity-operations",
        signer,
    )
    trust_path = root / "trust.json"
    _write_private(
        trust_path,
        ApprovalTrustRegistry(authorities=(authority,)).model_dump(mode="json"),
    )
    enabled = "entra.user.sessions.revoke"
    policy = _policy(
        manifest,
        authority,
        enabled_contracts=[enabled],
    )
    monkeypatch.setattr(
        server_module,
        "load_active_identity_manifest",
        lambda: manifest,
    )
    monkeypatch.setattr(
        server_module,
        "load_verified_governance_policy",
        lambda *_: SimpleNamespace(policy=policy),
    )
    settings = Settings(
        tenant_id=str(TENANT_ID),
        client_id="99999999-9999-4999-8999-999999999999",
        profile="write",
        modules="profile",
        write_enabled=True,
        identity_operations_enabled=True,
        token_cache_mode="memory",  # noqa: S106
        allowed_user_object_ids=str(USER_ID),
        governance_policy_path=root / "governance.json",
        governance_public_key_path=root / "governance.pub",
        operator_approval_dir=root / "approvals",
        operator_approval_trust_path=trust_path,
    )
    server = server_module.create_server(settings)
    identity_names = {
        tool.name
        for tool in server._tool_manager.list_tools()
        if tool.name.startswith("m365_entra_")
    }
    assert identity_names == {"m365_entra_user_sessions_revoke"}
