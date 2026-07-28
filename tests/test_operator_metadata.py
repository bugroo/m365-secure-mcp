from __future__ import annotations

import json
from pathlib import Path

from m365_secure_mcp.contract_manifest import (
    ContractEffect,
    RiskTier,
)
from m365_secure_mcp.operator_lifecycle import OperatorLifecycleStatus
from m365_secure_mcp.operator_metadata import (
    OperationMaturity,
    OperationPrivacyClass,
    project_operation_metadata,
)

from .operator_helpers import synthetic_contract


def test_experience_metadata_is_derived_from_contract_semantics() -> None:
    contract = synthetic_contract()
    metadata = project_operation_metadata(
        contract,
        maturity=OperationMaturity.EXPERIMENTAL,
    )
    assert metadata.operation_id == contract.id
    assert metadata.effect is ContractEffect.STATE_TRANSITION
    assert metadata.authorization_tier is RiskTier.T2
    assert metadata.approval_requirement == contract.authorization_mode
    assert metadata.annotations.readOnlyHint is False
    assert metadata.annotations.destructiveHint is True
    assert metadata.annotations.idempotentHint is True
    assert metadata.annotations.openWorldHint is True
    assert (
        metadata.privacy_class
        is OperationPrivacyClass.OPAQUE_PUBLIC_PRIVATE_CAPSULE
    )
    assert metadata.public_terminal_states == (
        OperatorLifecycleStatus.COMPLETED,
        OperatorLifecycleStatus.MANUAL_REVIEW_REQUIRED,
        OperatorLifecycleStatus.COMPENSATION_REQUIRED,
    )


def test_operator_evaluation_fixture_is_complete_synthetic_and_stable() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "evaluations/operator-foundation-adversarial.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schema_version"] == "1.0"
    assert document["evaluation_kind"] == "deterministic_security"
    assert document["contains_customer_data"] is False
    scenarios = document["scenarios"]
    ids = [item["id"] for item in scenarios]
    assert ids == sorted(ids)
    assert len(ids) == 10
    assert set(ids) == {
        "approval_bypass",
        "approval_replay",
        "async_not_verified",
        "changed_policy_digest",
        "changed_target",
        "expired_plan",
        "prompt_injection_authorization",
        "public_output_privacy",
        "repeated_signer",
        "uncertain_no_retry",
    }
    serialized = json.dumps(document, sort_keys=True).lower()
    assert "tenant_id" not in serialized
    assert "userprincipalname" not in serialized
    assert "private key" not in serialized
    for scenario in scenarios:
        test_path, test_name = scenario["test_reference"].split("::", 1)
        source = (root / test_path).read_text(encoding="utf-8")
        assert f"def {test_name.split('[')[0]}(" in source
