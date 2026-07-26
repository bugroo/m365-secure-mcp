from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest

from m365_secure_mcp.contract_manifest import (
    AuthorizationMode,
    load_global_manifest,
)
from m365_secure_mcp.governance import (
    GovernancePolicyError,
    GovernanceProfileName,
    load_policy_signer,
    load_verified_governance_policy,
    validate_policy_against_manifest,
)
from m365_secure_mcp.governance_cli import _generate_key

from .conftest import TENANT_ID
from .governance_helpers import write_signed_governance

TARGET_ID = "77777777-7777-4777-8777-777777777777"


def test_generated_governance_signer_is_passphrase_encrypted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = tmp_path / "signing"
    private_root.mkdir(mode=0o700)
    signer_path = private_root / "signer.pem"
    verifier_path = private_root / "signer.pub"
    responses = iter(["correct horse battery", "correct horse battery"])
    monkeypatch.setattr(
        "m365_secure_mcp.governance_cli.getpass.getpass",
        lambda _prompt: next(responses),
    )
    _generate_key(
        Namespace(
            signer=str(signer_path),
            verifier=str(verifier_path),
        )
    )
    assert b"ENCRYPTED PRIVATE KEY" in signer_path.read_bytes()
    assert b"correct horse battery" not in signer_path.read_bytes()
    assert load_policy_signer(
        signer_path,
        passphrase=b"correct horse battery",
    )


def test_signed_policy_authorizes_standing_t1(tmp_path: Path) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
    )
    verified = load_verified_governance_policy(policy_path, verifier_path)
    contract = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    )
    validate_policy_against_manifest(verified.policy, load_global_manifest())
    decision = verified.authorize(
        contract,
        tenant_id=TENANT_ID,
        target_user_id=TARGET_ID,
        local_target_user_ids=frozenset({TARGET_ID}),
    )
    assert decision.mode is AuthorizationMode.STANDING_POLICY
    assert decision.basis == "standing_policy"


def test_signed_privileged_read_authorizes_assurance_without_prompt(
    tmp_path: Path,
) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        active_profile=GovernanceProfileName.PRIVILEGED_READ,
    )
    verified = load_verified_governance_policy(policy_path, verifier_path)
    contract = load_global_manifest().contract(
        "entra.identity_governance.posture.snapshot"
    )

    decision = verified.authorize_read(
        contract,
        tenant_id=TENANT_ID,
    )

    assert decision.mode == "automatic_read"
    assert decision.basis == "signed_policy"
    assert decision.profile is GovernanceProfileName.PRIVILEGED_READ


def test_policy_can_only_tighten_authorization(tmp_path: Path) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
    )
    verified = load_verified_governance_policy(policy_path, verifier_path)
    contract = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    )
    decision = verified.authorize(
        contract,
        tenant_id=TENANT_ID,
        target_user_id=TARGET_ID,
        local_target_user_ids=frozenset({TARGET_ID}),
    )
    assert decision.mode is AuthorizationMode.EXPLICIT_PLAN
    assert decision.basis == "explicit_plan"

    document = verified.policy.model_copy(
        update={
            "authorization_overrides": {
                contract.id: AuthorizationMode.AUTOMATIC_READ
            }
        }
    )
    with pytest.raises(GovernancePolicyError, match="weaken"):
        validate_policy_against_manifest(document, load_global_manifest())


def test_policy_tampering_invalidates_signature(tmp_path: Path) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
    )
    document = json.loads(policy_path.read_text())
    document["policy"]["resources"]["protected_user_ids"] = [TARGET_ID]
    policy_path.write_text(json.dumps(document), encoding="utf-8")
    policy_path.chmod(0o600)
    with pytest.raises(GovernancePolicyError, match="digest mismatch"):
        load_verified_governance_policy(policy_path, verifier_path)


def test_protected_resource_is_fail_closed(tmp_path: Path) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        protected=True,
    )
    verified = load_verified_governance_policy(policy_path, verifier_path)
    contract = load_global_manifest().contract(
        "entra.user.operational_profile.update"
    )
    with pytest.raises(GovernancePolicyError, match="protected"):
        verified.authorize(
            contract,
            tenant_id=TENANT_ID,
            target_user_id=TARGET_ID,
            local_target_user_ids=frozenset({TARGET_ID}),
        )


def test_policy_change_is_detected_between_plan_and_execute(
    tmp_path: Path,
) -> None:
    policy_path, verifier_path = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
    )
    verified = load_verified_governance_policy(policy_path, verifier_path)
    replacement_policy, replacement_verifier = write_signed_governance(
        tmp_path / "replacement",
        tenant_id=TENANT_ID,
        user_id=TARGET_ID,
        authorization_mode=AuthorizationMode.EXPLICIT_PLAN,
    )
    policy_path.write_text(replacement_policy.read_text(), encoding="utf-8")
    policy_path.chmod(0o600)
    verifier_path.write_text(replacement_verifier.read_text(), encoding="ascii")
    verifier_path.chmod(0o600)
    with pytest.raises(GovernancePolicyError, match="changed after preflight"):
        verified.refresh()
