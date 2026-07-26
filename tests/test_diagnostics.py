from __future__ import annotations

from pathlib import Path

import pytest

from m365_secure_mcp.config import Settings
from m365_secure_mcp.diagnostics import doctor_report, permission_report

from .conftest import CLIENT_ID, TENANT_ID, USER_ID


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
        "allowed_user_object_ids": USER_ID,
        "allowed_upn_domains": "example.com",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_offline_doctor_is_secret_free_and_reports_exact_surface(
    tmp_path: Path,
) -> None:
    report = await doctor_report(
        make_settings(
            audit_log_path=tmp_path / "audit" / "events.jsonl",
            idempotency_db_path=tmp_path / "receipts" / "writes.sqlite3",
        ),
        live=False,
    )

    assert report["overall"] == "pass"
    assert report["mode"] == "offline"
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["tool_surface"]["evidence"]["tools"] == [
        "m365_get_my_profile",
        "m365_get_security_posture",
    ]
    assert checks["no_delete_surface"]["status"] == "pass"
    assert checks["result_contract"]["status"] == "pass"
    assert checks["private_state_paths"]["status"] == "pass"
    assert checks["private_api_scope"]["evidence"]["scopes"] == ["User.Read"]
    assert "access_token" not in str(report).lower()


@pytest.mark.asyncio
async def test_permission_explanation_and_policy_digest_are_effective() -> None:
    settings = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="planner.update_task_details",
        allowed_plan_ids="plan-1",
    )

    explanation = settings.permission_explanation()
    assert explanation["effective_scopes"] == ["Tasks.ReadWrite", "User.Read"]
    assert explanation["private_api_scope_required"] is False
    assert explanation["write_action_scope_reasons"] == [
        {
            "action": "planner.update_task_details",
            "resource": "graph",
            "scopes": ["Tasks.ReadWrite"],
        }
    ]
    assert settings.policy_digest.startswith("sha256:")
    assert settings.policy_digest != make_settings(modules="profile,mail").policy_digest
    changed_plan = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="planner.update_task_details",
        allowed_plan_ids="plan-2",
    )
    assert settings.policy_digest != changed_plan.policy_digest

    report = await permission_report(settings)
    contracts = {item["tool"]: item for item in report["tool_contracts"]}
    planner_contract = contracts["m365_update_planner_task_details"]
    assert planner_contract["scopes"] == ["Tasks.ReadWrite", "User.Read"]
    assert planner_contract["resources"] == {
        "graph": ["Tasks.ReadWrite", "User.Read"]
    }
    assert planner_contract["reason"] == (
        "enabled write action: planner.update_task_details"
    )
    assert contracts["m365_get_write_operation"]["scopes"] == []
    assert report["scope_to_tools"]["Tasks.ReadWrite"] == [
        "m365_update_planner_task_details"
    ]
