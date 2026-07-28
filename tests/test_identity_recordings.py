from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORDING = ROOT / "tests/recordings/identity/identity-slice-v1.json"
KNOWN_SYNTHETIC_IDS = {
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
}
UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def test_identity_recording_playback_is_complete_and_deterministic() -> None:
    document = json.loads(RECORDING.read_text())
    assert document["schema_version"] == "1.0"
    assert document["recording_mode"] == "sanitized-synthetic"
    assert document["updated_only_by_explicit_action"] is True
    transcripts = document["transcripts"]
    assert [item["operation_id"] for item in transcripts] == sorted(
        item["operation_id"] for item in transcripts
    )
    assert {item["operation_id"] for item in transcripts} == {
        "entra.user.sessions.revoke",
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
        "entra.user.direct_license.set",
    }
    assert all(len(item["provider_sequence"]) == 3 for item in transcripts)
    assert {
        item["expected_kind"] for item in transcripts
    } == {"accepted", "verified"}


def test_identity_recording_privacy_scan_rejects_unapproved_identifiers() -> None:
    payload = RECORDING.read_text()
    lowered = payload.lower()
    assert "@" not in payload
    assert "tenant_id" not in lowered
    assert "userprincipalname" not in lowered
    assert "displayname" not in lowered
    assert "ipaddress" not in lowered
    assert "deviceid" not in lowered
    assert "request-id" not in lowered
    assert set(UUID_PATTERN.findall(payload)) == KNOWN_SYNTHETIC_IDS
    assert "begin private key" not in lowered
    assert "begin encrypted private key" not in lowered


def test_live_identity_lab_harness_is_disabled_by_default() -> None:
    assert os.environ.get("M365_IDENTITY_LIVE_LAB") != "1"


@pytest.mark.skipif(
    os.environ.get("M365_IDENTITY_LIVE_LAB") != "1",
    reason="explicit non-production lab opt-in is required",
)
def test_live_identity_lab_requires_external_reviewed_harness() -> None:
    assert os.environ.get("M365_LAB_PROFILE") == "lab-only"
    assert os.environ.get("M365_LAB_TENANT_ID")
    pytest.skip(
        "The network runner is external and remains disabled until the "
        "production candidate-signing ceremony."
    )
