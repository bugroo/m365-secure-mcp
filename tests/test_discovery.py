from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from m365_secure_mcp.config import Settings
from m365_secure_mcp.discovery import discover_resources

from .conftest import CLIENT_ID, TENANT_ID, USER_ID

APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
CONDITIONAL_ACCESS_POLICY_ID = "66666666-6666-4666-8666-666666666666"


class FakeDiscoveryGraph:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        del params, json_body, headers
        self.calls.append((method, endpoint))
        if endpoint == "/me/planner/plans":
            return {
                "value": [
                    {"id": "plan-2", "title": "Second plan"},
                    {"id": "plan-1", "title": "First plan"},
                ]
            }
        if endpoint == "/me/joinedTeams":
            return {
                "value": [
                    {
                        "id": "team-1",
                        "displayName": "Operations",
                        "description": "Approved team",
                    }
                ]
            }
        if endpoint == "/applications":
            return {
                "value": [
                    {
                        "id": APPLICATION_ID,
                        "appId": "77777777-7777-4777-8777-777777777777",
                        "displayName": "Internal application",
                    }
                ]
            }
        if endpoint == "/servicePrincipals":
            return {
                "value": [
                    {
                        "id": SERVICE_PRINCIPAL_ID,
                        "appId": "77777777-7777-4777-8777-777777777777",
                        "displayName": "Internal enterprise app",
                    }
                ]
            }
        if endpoint == "/identity/conditionalAccess/policies":
            return {
                "value": [
                    {
                        "id": CONDITIONAL_ACCESS_POLICY_ID,
                        "displayName": "Report-only baseline",
                        "state": "enabledForReportingButNotEnforced",
                    }
                ]
            }
        raise AssertionError(f"unexpected endpoint: {endpoint}")


def make_settings(tmp_path: Path) -> Settings:
    return Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        allowed_user_object_ids=USER_ID,
        allowed_upn_domains="example.com",
        allowed_plan_ids="plan-1",
        allowed_team_ids="team-2",
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
        allowed_conditional_access_policy_ids=(
            CONDITIONAL_ACCESS_POLICY_ID
        ),
        audit_log_path=tmp_path / "audit.jsonl",
        idempotency_db_path=tmp_path / "writes.sqlite3",
    )


@pytest.mark.asyncio
async def test_operator_discovery_is_read_only_and_does_not_change_policy(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    digest_before = settings.policy_digest
    graph = FakeDiscoveryGraph()

    report = await discover_resources(
        settings,
        frozenset({"planner", "teams"}),
        graph=graph,
    )

    assert graph.calls == [
        ("GET", "/me/planner/plans"),
        ("GET", "/me/joinedTeams"),
    ]
    assert report["read_only"] is True
    assert report["mcp_tool_exposed"] is False
    assert report["policy_changed"] is False
    assert settings.policy_digest == digest_before
    plans = report["resources"]["planner"]["candidates"]
    assert [item["id"] for item in plans] == ["plan-1", "plan-2"]
    assert plans[0]["currently_allowlisted"] is True
    assert plans[1]["currently_allowlisted"] is False
    assert report["resources"]["teams"]["candidates"][0][
        "currently_allowlisted"
    ] is False
    assert {
        "Tasks.Read",
        "Team.ReadBasic.All",
        "User.Read",
    } == set(report["requested_scopes"])


@pytest.mark.asyncio
async def test_operator_discovery_rejects_unknown_kind(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="discovery kinds"):
        await discover_resources(
            make_settings(tmp_path),
            frozenset({"unknown"}),
            graph=FakeDiscoveryGraph(),
        )


@pytest.mark.asyncio
async def test_privileged_resource_discovery_is_explicit_read_only_and_bounded(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    digest_before = settings.policy_digest
    graph = FakeDiscoveryGraph()

    report = await discover_resources(
        settings,
        frozenset(
            {
                "applications",
                "service_principals",
                "conditional_access",
            }
        ),
        graph=graph,
    )

    assert graph.calls == [
        ("GET", "/applications"),
        ("GET", "/identity/conditionalAccess/policies"),
        ("GET", "/servicePrincipals"),
    ]
    assert set(report["requested_scopes"]) == {
        "Application.Read.All",
        "Policy.Read.All",
        "User.Read",
    }
    assert report["policy_changed"] is False
    assert settings.policy_digest == digest_before
    assert report["resources"]["applications"]["candidates"][0][
        "currently_allowlisted"
    ] is True
    assert report["resources"]["service_principals"]["candidates"][0][
        "currently_allowlisted"
    ] is True
    assert report["resources"]["conditional_access"]["candidates"][0][
        "currently_allowlisted"
    ] is True
