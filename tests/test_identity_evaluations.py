from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_identity_agent_evaluation_is_closed_and_candidate_only() -> None:
    document = json.loads(
        (ROOT / "evaluations/identity-slice-candidate.json").read_text()
    )
    assert document["schema_version"] == "1.0"
    assert document["candidate_manifest_required"] is True
    assert document["contains_customer_data"] is False
    scenarios = document["scenarios"]
    ids = [item["id"] for item in scenarios]
    assert ids == sorted(ids)
    assert len(ids) == 11
    expected = {item["expected"] for item in scenarios}
    assert {
        "entra.user.sessions.revoke",
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
        "entra.user.direct_license.set",
        "no_write",
        "awaiting_external_approval",
        "blocked_precondition",
        "accepted_not_verified",
        "manual_review_no_retry",
    } <= expected
    serialized = json.dumps(document, sort_keys=True).lower()
    assert "tenant_id" not in serialized
    assert "userprincipalname" not in serialized
    assert "endpoint" not in serialized
    assert "scope" not in serialized
    assert "request_body" not in serialized
