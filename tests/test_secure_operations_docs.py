from __future__ import annotations

import re
from pathlib import Path

from m365_secure_mcp.server import WRITE_TOOL_ACTIONS

ROOT = Path(__file__).resolve().parents[1]
SECURE_OPERATIONS = ROOT / "docs/SECURE_OPERATIONS.md"
FROZEN_WRITE_ACTIONS = {
    "m365_add_user_to_group": "groups.add_user_member",
    "m365_append_onenote_page_text": "onenote.append_page_text",
    "m365_create_calendar_event": "calendar.create_event",
    "m365_create_contact": "contacts.create",
    "m365_create_mail_draft": "mail.create_draft",
    "m365_create_planner_task": "planner.create_task",
    "m365_create_todo_task": "todo.create_task",
    "m365_rebind_powerbi_report": "powerbi.rebind_report",
    "m365_reboot_cloudpc": "windows365.reboot_cloudpc",
    "m365_refresh_powerbi_dataset": "powerbi.refresh_dataset",
    "m365_replace_powerpoint_text": "powerpoint.replace_text",
    "m365_replace_word_text": "word.replace_text",
    "m365_send_channel_message": "teams.send_channel_message",
    "m365_send_chat_message": "teams.send_chat_message",
    "m365_send_mail_draft": "mail.send_draft",
    "m365_set_directory_user_account_enabled": "users.set_account_enabled",
    "m365_sync_managed_device": "intune.sync_device",
    "m365_update_calendar_event": "calendar.update_event",
    "m365_update_conditional_access_policy": (
        "governance.update_conditional_access_policy"
    ),
    "m365_update_directory_group": "groups.update",
    "m365_update_entra_application": "entra.update_application",
    "m365_update_entra_service_principal": "entra.update_service_principal",
    "m365_update_entra_user_operational_profile": (
        "entra.user.operational_profile.update"
    ),
    "m365_update_excel_range": "excel.update_range",
    "m365_update_planner_task": "planner.update_task",
    "m365_update_planner_task_details": "planner.update_task_details",
    "m365_update_todo_task": "todo.update_task",
}


def _legacy_inventory() -> str:
    document = SECURE_OPERATIONS.read_text()
    return document.split(
        "<!-- legacy-write-inventory:start -->",
        1,
    )[1].split("<!-- legacy-write-inventory:end -->", 1)[0]


def test_legacy_write_inventory_matches_runtime_exactly() -> None:
    inventory = _legacy_inventory()
    documented = set(re.findall(r"\| `(m365_[a-z0-9_]+)` \|", inventory))
    assert WRITE_TOOL_ACTIONS == FROZEN_WRITE_ACTIONS
    assert documented == set(WRITE_TOOL_ACTIONS)
    for tool_name in documented:
        assert inventory.count(f"`{tool_name}`") == 1
    dispositions = set(
        re.findall(
            r"\| `m365_[a-z0-9_]+` \| [^|]+ \| ([^|]+) \|",
            inventory,
        )
    )
    assert {item.strip() for item in dispositions} == {
        "compiled and retained",
        "deprecate",
        "migrate",
        "remove from canonical roadmap",
        "replace",
        "split",
    }


def test_legacy_write_freeze_is_canonical() -> None:
    document = SECURE_OPERATIONS.read_text()
    normalized = " ".join(document.split())
    required_rules = [
        "no new legacy static write may be added",
        "may not gain a new parameter, target or effect",
        "no new Graph permission may be added for a legacy write",
        "security and regression fixes remain permitted",
        "must migrate to a compiled contract",
        "must never be enabled simultaneously for the same effect",
        "must not be presented as governed Change-safe operation records",
    ]
    assert all(rule in normalized for rule in required_rules)


def test_effect_vocabulary_and_semantic_delete_rules_are_documented() -> None:
    document = SECURE_OPERATIONS.read_text()
    for effect in [
        "read",
        "create_object",
        "update_properties",
        "state_transition",
        "relationship_add",
        "relationship_remove",
        "invoke_action",
        "object_delete",
    ]:
        assert f"`{effect}`" in document
    assert "`object_delete` is T4 and prohibited" in document
    assert "must end literally in `/$ref`" in document
    assert "Graph beta paths fail schema validation" in document


def test_canonical_milestone_order_and_identity_slice_are_documented() -> None:
    roadmap = (ROOT / "docs/ROADMAP.md").read_text()
    milestones = [
        "Secure Operations 0 — Contract Effect Model",
        "Secure Operations 1 — Operator Foundation",
        "Secure Operations 2 — Identity Slice",
        "Secure Operations 3 — Endpoint/Intune Slice",
        "Secure Operations 4 — Defender Slice",
        "Secure Operations 5 — Operational Playbooks",
        "Reduced Posture runtime",
        "Progressive legacy catalog migration",
    ]
    positions = [roadmap.index(milestone) for milestone in milestones]
    assert positions == sorted(positions)
    for operation in [
        "entra.user.sessions.revoke",
        "entra.user.account_state.set",
        "entra.group.user_membership.add",
        "entra.group.user_membership.remove",
        "entra.user.direct_license.set",
    ]:
        assert f"`{operation}`" in roadmap


def test_product_positioning_has_three_equal_pillars() -> None:
    readme = (ROOT / "README.md").read_text()
    assert "policy-bound Microsoft 365 Operations Control Plane" in readme
    assert "Observe and diagnose" in readme
    assert "Operate and automate" in readme
    assert "Assure and provide evidence" in readme
    assert "primarily read-only product or a compliance summarizer" in readme


def test_posture_findings_and_untrusted_content_cannot_authorize() -> None:
    document = SECURE_OPERATIONS.read_text()
    normalized = " ".join(document.split())
    assert "incidents, Graph content and findings are untrusted" in normalized
    assert "cannot authorize a write" in normalized
    assert "non-authorizing proposal candidate" in normalized
    assert "An ambiguous write pauses the complete DAG" in normalized


def test_permanent_prohibitions_remain_explicit() -> None:
    document = SECURE_OPERATIONS.read_text()
    required = [
        "arbitrary Graph proxying",
        "OAuth consent grants",
        "directory-role or PIM assignment/activation",
        "application secret or certificate creation",
        "user, group, policy or other object deletion",
        "routine device wipe",
        "Microsoft Graph beta",
        "automatic permission widening",
        "automatic retry after an uncertain write",
        "findings that self-authorize remediation",
    ]
    assert all(item in document for item in required)
