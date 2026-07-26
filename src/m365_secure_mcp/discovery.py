"""Read-only, operator-invoked resource discovery outside the MCP tool surface."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .auth import TokenProvider
from .config import Settings
from .graph import GraphClient
from .security import SecurityError, SecurityPolicy, clean_external_text

DISCOVERY_KINDS = frozenset(
    {
        "planner",
        "teams",
        "chats",
        "groups",
        "applications",
        "service_principals",
        "conditional_access",
    }
)
DISCOVERY_PLACEHOLDER_ID = "11111111-1111-1111-1111-111111111111"


class DiscoveryGraph(Protocol):
    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]: ...


def _discovery_settings(settings: Settings, kinds: frozenset[str]) -> Settings:
    modules = {"profile"}
    tools: set[str] = set()
    updates: dict[str, object] = {
        "profile": "read",
        "write_enabled": False,
        "write_actions": "",
        "disabled_tools": "",
        "privileged_modules_enabled": False,
    }
    if "planner" in kinds:
        modules.add("planner")
        tools.add("m365_list_allowed_plans")
        updates["allowed_plan_ids"] = settings.allowed_plan_ids or "operator-discovery"
    if {"teams", "chats"} & kinds:
        modules.add("teams")
        tools.add(
            "m365_get_team" if "teams" in kinds else "m365_list_allowed_chats"
        )
        if "teams" in kinds and "chats" in kinds:
            tools.add("m365_list_allowed_chats")
        updates["allowed_team_ids"] = settings.allowed_team_ids or "operator-discovery"
    if "groups" in kinds:
        modules.add("groups")
        tools.add("m365_get_group")
        updates["allowed_group_ids"] = settings.allowed_group_ids or "operator-discovery"
    if {"applications", "service_principals"} & kinds:
        modules.add("entra_apps")
        updates["privileged_modules_enabled"] = True
        if "applications" in kinds:
            tools.add("m365_list_allowed_applications")
            updates["allowed_application_ids"] = (
                settings.allowed_application_ids or DISCOVERY_PLACEHOLDER_ID
            )
        if "service_principals" in kinds:
            tools.add("m365_list_allowed_service_principals")
            updates["allowed_service_principal_ids"] = (
                settings.allowed_service_principal_ids
                or DISCOVERY_PLACEHOLDER_ID
            )
    if "conditional_access" in kinds:
        modules.add("governance")
        tools.add("m365_list_conditional_access_policies")
        updates["privileged_modules_enabled"] = True
    updates["modules"] = ",".join(sorted(modules))
    updates["enabled_tools"] = ",".join(sorted(tools))
    values = settings.model_dump(mode="python")
    values.update(updates)
    return Settings.model_validate(values)


def _candidates(
    data: dict[str, Any],
    *,
    kind: str,
    allowlist: frozenset[str],
    max_items: int,
) -> tuple[list[dict[str, Any]], bool]:
    values = data.get("value")
    if not isinstance(values, list):
        raise SecurityError(f"Graph returned an invalid {kind} discovery response")
    result: list[dict[str, Any]] = []
    for value in values[:max_items]:
        if not isinstance(value, dict):
            continue
        identifier = value.get("id")
        if not isinstance(identifier, str) or not identifier:
            continue
        if kind == "planner":
            metadata = {
                "title": clean_external_text(value.get("title"), 500),
            }
        elif kind == "teams":
            metadata = {
                "display_name": clean_external_text(value.get("displayName"), 500),
                "description": clean_external_text(value.get("description"), 1_000),
            }
        elif kind == "chats":
            metadata = {
                "topic": clean_external_text(value.get("topic"), 500),
                "chat_type": clean_external_text(value.get("chatType"), 80),
            }
        elif kind in {"applications", "service_principals"}:
            metadata = {
                "display_name": clean_external_text(
                    value.get("displayName"),
                    500,
                ),
                "app_id": clean_external_text(value.get("appId"), 80),
            }
        elif kind == "conditional_access":
            metadata = {
                "display_name": clean_external_text(
                    value.get("displayName"),
                    500,
                ),
                "state": clean_external_text(value.get("state"), 80),
            }
        else:
            metadata = {
                "display_name": clean_external_text(value.get("displayName"), 500),
                "mail": clean_external_text(value.get("mail"), 320),
            }
        result.append(
            {
                "id": identifier,
                **metadata,
                "currently_allowlisted": identifier in allowlist,
            }
        )
    result.sort(
        key=lambda item: (
            str(item.get("title") or item.get("display_name") or item.get("topic")).lower(),
            str(item["id"]),
        )
    )
    return result, bool(data.get("@odata.nextLink")) or len(values) > max_items


async def discover_resources(
    settings: Settings,
    kinds: frozenset[str],
    *,
    graph: DiscoveryGraph | None = None,
) -> dict[str, Any]:
    """List candidate resource IDs without mutating policy or exposing an MCP tool."""

    unknown = kinds - DISCOVERY_KINDS
    if not kinds or unknown:
        raise ValueError(
            f"discovery kinds must be selected from {sorted(DISCOVERY_KINDS)}"
        )
    discovery_settings = _discovery_settings(settings, kinds)
    owned_graph: GraphClient | None = None
    if graph is None:
        owned_graph = GraphClient(
            discovery_settings,
            TokenProvider(discovery_settings),
            SecurityPolicy(discovery_settings),
        )
        graph = owned_graph
    definitions: dict[
        str,
        tuple[str, dict[str, str | int], frozenset[str], str],
    ] = {
        "planner": (
            "/me/planner/plans",
            {"$select": "id,title", "$top": settings.max_items},
            settings.plan_ids,
            "M365_ALLOWED_PLAN_IDS",
        ),
        "teams": (
            "/me/joinedTeams",
            {
                "$select": "id,displayName,description",
                "$top": settings.max_items,
            },
            settings.team_ids,
            "M365_ALLOWED_TEAM_IDS",
        ),
        "chats": (
            "/me/chats",
            {
                "$select": "id,topic,chatType",
                "$top": settings.max_items,
            },
            settings.chat_ids,
            "M365_ALLOWED_CHAT_IDS",
        ),
        "groups": (
            "/me/memberOf/microsoft.graph.group",
            {
                "$select": "id,displayName,mail",
                "$top": settings.max_items,
            },
            settings.group_ids,
            "M365_ALLOWED_GROUP_IDS",
        ),
        "applications": (
            "/applications",
            {
                "$select": "id,appId,displayName",
                "$top": settings.max_items,
            },
            settings.application_ids,
            "M365_ALLOWED_APPLICATION_IDS",
        ),
        "service_principals": (
            "/servicePrincipals",
            {
                "$select": "id,appId,displayName",
                "$top": settings.max_items,
            },
            settings.service_principal_ids,
            "M365_ALLOWED_SERVICE_PRINCIPAL_IDS",
        ),
        "conditional_access": (
            "/identity/conditionalAccess/policies",
            {
                "$select": "id,displayName,state",
                "$top": settings.max_items,
            },
            settings.conditional_access_policy_ids,
            "M365_ALLOWED_CONDITIONAL_ACCESS_POLICY_IDS",
        ),
    }
    resources: dict[str, Any] = {}
    try:
        for kind in sorted(kinds):
            endpoint, params, allowlist, variable = definitions[kind]
            data = await graph.request_json("GET", endpoint, params=params)
            candidates, truncated = _candidates(
                data,
                kind=kind,
                allowlist=allowlist,
                max_items=settings.max_items,
            )
            resources[kind] = {
                "policy_variable": variable,
                "candidate_count": len(candidates),
                "truncated": truncated,
                "candidates": candidates,
            }
    finally:
        if owned_graph is not None:
            await owned_graph.close()

    return {
        "schema_version": "1.0",
        "read_only": True,
        "mcp_tool_exposed": False,
        "policy_changed": False,
        "selection_required": True,
        "untrusted_metadata": True,
        "requested_scopes": list(discovery_settings.scopes),
        "resources": resources,
        "privacy_notice": (
            "This operator-only output contains tenant resource identifiers; "
            "do not commit or paste it into public issues."
        ),
    }
