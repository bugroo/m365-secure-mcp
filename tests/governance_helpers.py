from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    load_global_manifest,
    sha256_digest,
)
from m365_secure_mcp.governance import (
    ApplicationCredentialBaseline,
    GovernancePolicy,
    GovernanceProfile,
    GovernanceProfileName,
    GovernanceResources,
    IdentityGovernanceBaseline,
    PermissionGrantBaseline,
    public_key_text,
    sign_governance_policy,
    validate_policy_against_manifest,
)
from m365_secure_mcp.playbook_manifest import load_global_playbook_manifest


def write_signed_governance(
    root: Path,
    *,
    tenant_id: str,
    user_id: str,
    authorization_mode: AuthorizationMode | None = None,
    protected: bool = False,
    enable_write_contract: bool = True,
    active_profile: GovernanceProfileName = (
        GovernanceProfileName.ROUTINE_WRITE
    ),
    identity_governance_baseline: IdentityGovernanceBaseline | None = None,
    permission_grant_baseline: PermissionGrantBaseline | None = None,
    service_principal_id: str | None = None,
    application_credential_baseline: ApplicationCredentialBaseline | None = None,
    application_id: str | None = None,
    enable_workload_identity_readiness: bool = False,
) -> tuple[Path, Path]:
    """Create owner-only test policy material outside the repository."""

    private_root = root / "governance"
    private_root.mkdir(mode=0o700, parents=True)
    private_root.chmod(0o700)
    manifest = load_global_manifest()
    playbooks = load_global_playbook_manifest(manifest)
    readiness_playbook = "entra.workload_identity.readiness.playbook"
    write_contract = "entra.user.operational_profile.update"
    profiles = {
        GovernanceProfileName.ROUTINE_READ: GovernanceProfile(
            enabled_contracts=[
                "entra.organization.summary.read",
                "entra.user.operational_profile.read",
            ]
        ),
        GovernanceProfileName.ROUTINE_WRITE: GovernanceProfile(
            enabled_contracts=[write_contract] if enable_write_contract else []
        ),
        GovernanceProfileName.PRIVILEGED_READ: GovernanceProfile(
            enabled_contracts=[
                "entra.app_credentials.posture.snapshot",
                "entra.conditional_access.policies.read",
                "entra.identity_governance.posture.snapshot",
                "entra.permission_grants.drift.snapshot",
                "entra.role_assignments.read",
            ],
            enabled_playbooks=(
                [readiness_playbook]
                if enable_workload_identity_readiness
                else []
            ),
        ),
        GovernanceProfileName.SELECTED_WRITE: GovernanceProfile(),
        GovernanceProfileName.BREAK_GLASS: GovernanceProfile(
            break_glass_ttl_seconds=900
        ),
    }
    policy = GovernancePolicy(
        tenant_id=UUID(tenant_id),
        active_profile=active_profile,
        profiles=profiles,
        resources=GovernanceResources(
            tenants=[UUID(tenant_id)],
            users=[UUID(user_id)],
            applications=(
                [UUID(application_id)]
                if application_id is not None
                else []
            ),
            service_principals=(
                [UUID(service_principal_id)]
                if service_principal_id is not None
                else []
            ),
            protected_user_ids=[UUID(user_id)] if protected else [],
        ),
        authorization_overrides=(
            {write_contract: authorization_mode}
            if authorization_mode is not None
            else {}
        ),
        identity_governance_baseline=identity_governance_baseline,
        permission_grant_baseline=permission_grant_baseline,
        application_credential_baseline=application_credential_baseline,
        contract_manifest_digest=sha256_digest(manifest),
        playbook_manifest_digest=(
            sha256_digest(playbooks)
            if enable_workload_identity_readiness
            else None
        ),
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    validate_policy_against_manifest(policy, manifest, playbooks)
    signer = Ed25519PrivateKey.generate()
    bundle = sign_governance_policy(policy, signer, key_id="test-governance")

    verifier_path = private_root / "governance.pub"
    verifier_path.write_text(public_key_text(signer), encoding="ascii")
    verifier_path.chmod(0o600)
    policy_path = private_root / "governance.signed.json"
    policy_path.write_text(
        json.dumps(
            bundle.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    return policy_path, verifier_path
