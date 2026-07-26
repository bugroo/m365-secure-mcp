"""Read-only, operator-invoked resource discovery outside the MCP tool surface."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .auth import TokenProvider
from .config import POWERBI_RESOURCE, Settings
from .graph import GraphClient
from .powerbi import PowerBIClient
from .security import SecurityError, SecurityPolicy, clean_external_text

DISCOVERY_KINDS = frozenset(
    {
        "planner",
        "teams",
        "chats",
        "groups",
        "users",
        "directory_devices",
        "managed_devices",
        "cloudpcs",
        "drives",
        "powerbi_workspaces",
        "powerbi_content",
        "applications",
        "service_principals",
        "conditional_access",
        "ediscovery_cases",
        "retention_labels",
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


class DiscoveryPowerBI(Protocol):
    async def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, str | int] | None = None,
        json_body: Mapping[str, Any] | None = None,
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
    if "users" in kinds:
        modules.add("users_admin")
        tools.add("m365_list_allowed_users")
        updates["allowed_target_user_ids"] = (
            settings.allowed_target_user_ids or DISCOVERY_PLACEHOLDER_ID
        )
        updates["privileged_modules_enabled"] = True
    if "directory_devices" in kinds:
        modules.add("directory_devices")
        tools.add("m365_list_allowed_directory_devices")
        updates["allowed_device_ids"] = (
            settings.allowed_device_ids or DISCOVERY_PLACEHOLDER_ID
        )
        updates["privileged_modules_enabled"] = True
    if "managed_devices" in kinds:
        modules.add("intune")
        tools.add("m365_list_managed_devices")
        updates["privileged_modules_enabled"] = True
    if "cloudpcs" in kinds:
        modules.add("windows365")
        tools.add("m365_list_allowed_cloudpcs")
        updates["allowed_cloudpc_ids"] = (
            settings.allowed_cloudpc_ids or DISCOVERY_PLACEHOLDER_ID
        )
        updates["privileged_modules_enabled"] = True
    if "drives" in kinds:
        modules.add("files")
        tools.add("m365_list_onedrive_root")
    if "powerbi_content" in kinds and not settings.powerbi_workspace_ids:
        raise ValueError(
            "powerbi_content discovery requires "
            "M365_ALLOWED_POWERBI_WORKSPACE_IDS"
        )
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
    if {"ediscovery_cases", "retention_labels"} & kinds:
        modules.add("compliance")
        updates["privileged_modules_enabled"] = True
        if "ediscovery_cases" in kinds:
            tools.add("m365_list_allowed_ediscovery_cases")
            updates["allowed_ediscovery_case_ids"] = (
                settings.allowed_ediscovery_case_ids
                or DISCOVERY_PLACEHOLDER_ID
            )
        if "retention_labels" in kinds:
            tools.add("m365_list_allowed_retention_labels")
            updates["allowed_retention_label_ids"] = (
                settings.allowed_retention_label_ids
                or DISCOVERY_PLACEHOLDER_ID
            )
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
        metadata: dict[str, Any]
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
        elif kind == "ediscovery_cases":
            metadata = {
                "display_name": clean_external_text(
                    value.get("displayName"),
                    500,
                ),
                "status": clean_external_text(value.get("status"), 80),
                "external_id": clean_external_text(
                    value.get("externalId"),
                    200,
                ),
            }
        elif kind == "retention_labels":
            metadata = {
                "display_name": clean_external_text(
                    value.get("displayName"),
                    500,
                ),
                "in_use": bool(value.get("isInUse")),
                "retention_trigger": clean_external_text(
                    value.get("retentionTrigger"),
                    100,
                ),
            }
        elif kind == "directory_devices":
            metadata = {
                "display_name": clean_external_text(
                    value.get("displayName"),
                    500,
                ),
                "device_id": clean_external_text(
                    value.get("deviceId"),
                    80,
                ),
                "operating_system": clean_external_text(
                    value.get("operatingSystem"),
                    100,
                ),
            }
        elif kind == "managed_devices":
            metadata = {
                "display_name": clean_external_text(
                    value.get("deviceName"),
                    500,
                ),
                "operating_system": clean_external_text(
                    value.get("operatingSystem"),
                    100,
                ),
                "compliance_state": clean_external_text(
                    value.get("complianceState"),
                    100,
                ),
            }
        elif kind == "cloudpcs":
            metadata = {
                "display_name": clean_external_text(
                    value.get("displayName"),
                    500,
                ),
                "status": clean_external_text(value.get("status"), 100),
                "user_principal_name": clean_external_text(
                    value.get("userPrincipalName"),
                    320,
                ),
            }
        elif kind == "drives":
            metadata = {
                "display_name": clean_external_text(
                    value.get("name"),
                    500,
                ),
                "drive_type": clean_external_text(
                    value.get("driveType"),
                    100,
                ),
            }
        elif kind == "powerbi_workspaces":
            metadata = {
                "display_name": clean_external_text(
                    value.get("name"),
                    500,
                ),
                "workspace_type": clean_external_text(
                    value.get("type"),
                    100,
                ),
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
    powerbi: DiscoveryPowerBI | None = None,
) -> dict[str, Any]:
    """List candidate resource IDs without mutating policy or exposing an MCP tool."""

    unknown = kinds - DISCOVERY_KINDS
    if not kinds or unknown:
        raise ValueError(
            f"discovery kinds must be selected from {sorted(DISCOVERY_KINDS)}"
        )
    discovery_settings = _discovery_settings(settings, kinds)
    full_graph_scopes = tuple(
        sorted(
            {
                *settings.scopes,
                *discovery_settings.scopes,
            }
        )
    )
    owned_graph: GraphClient | None = None
    owned_powerbi: PowerBIClient | None = None
    if graph is None:
        owned_graph = GraphClient(
            discovery_settings,
            TokenProvider(
                discovery_settings,
                scopes=full_graph_scopes,
            ),
            SecurityPolicy(discovery_settings),
        )
        graph = owned_graph
    requested_powerbi_scopes: set[str] = set()
    if "powerbi_workspaces" in kinds:
        requested_powerbi_scopes.add("Workspace.Read.All")
    if "powerbi_content" in kinds:
        requested_powerbi_scopes.update(
            {
                "Report.Read.All",
                "Dataset.Read.All",
                "Dashboard.Read.All",
            }
        )
    discovery_powerbi_scopes = {
        f"{POWERBI_RESOURCE}/{scope}"
        for scope in requested_powerbi_scopes
    }
    full_powerbi_scopes = tuple(
        sorted(
            {
                *settings.powerbi_scopes,
                *discovery_powerbi_scopes,
            }
        )
    )
    if requested_powerbi_scopes and powerbi is None:
        if owned_graph is None:
            raise ValueError(
                "Power BI discovery with an injected Graph client also "
                "requires an injected Power BI client"
            )
        owned_powerbi = PowerBIClient(
            discovery_settings,
            TokenProvider(
                discovery_settings,
                scopes=full_powerbi_scopes,
                resource="powerbi",
            ),
            ensure_principal=owned_graph.ensure_principal,
        )
        powerbi = owned_powerbi
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
        "users": (
            "/users",
            {
                "$select": "id,displayName,mail,userPrincipalName",
                "$top": settings.max_items,
            },
            settings.target_user_ids,
            "M365_ALLOWED_TARGET_USER_IDS",
        ),
        "directory_devices": (
            "/devices",
            {
                "$select": (
                    "id,deviceId,displayName,operatingSystem"
                ),
                "$top": settings.max_items,
            },
            settings.device_ids,
            "M365_ALLOWED_DEVICE_IDS",
        ),
        "managed_devices": (
            "/deviceManagement/managedDevices",
            {
                "$select": (
                    "id,deviceName,operatingSystem,complianceState"
                ),
                "$top": settings.max_items,
            },
            settings.managed_device_ids,
            "M365_ALLOWED_MANAGED_DEVICE_IDS",
        ),
        "cloudpcs": (
            "/deviceManagement/virtualEndpoint/cloudPCs",
            {
                "$select": "id,displayName,status,userPrincipalName",
                "$top": settings.max_items,
            },
            settings.cloudpc_ids,
            "M365_ALLOWED_CLOUDPC_IDS",
        ),
        "drives": (
            "/me/drives",
            {
                "$select": "id,name,driveType,webUrl",
                "$top": settings.max_items,
            },
            settings.drive_ids,
            "M365_ALLOWED_DRIVE_IDS",
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
        "ediscovery_cases": (
            "/security/cases/ediscoveryCases",
            {
                "$select": (
                    "id,displayName,status,externalId,"
                    "createdDateTime,lastModifiedDateTime"
                ),
                "$top": settings.max_items,
            },
            settings.ediscovery_case_ids,
            "M365_ALLOWED_EDISCOVERY_CASE_IDS",
        ),
        "retention_labels": (
            "/security/labels/retentionLabels",
            {},
            settings.retention_label_ids,
            "M365_ALLOWED_RETENTION_LABEL_IDS",
        ),
    }
    resources: dict[str, Any] = {}
    try:
        for kind in sorted(kinds):
            if kind == "powerbi_workspaces":
                if powerbi is None:
                    raise SecurityError(
                        "Power BI discovery client is unavailable"
                    )
                data = await powerbi.request_json("GET", "/groups")
                candidates, truncated = _candidates(
                    data,
                    kind=kind,
                    allowlist=settings.powerbi_workspace_ids,
                    max_items=settings.max_items,
                )
                resources[kind] = {
                    "policy_variable": (
                        "M365_ALLOWED_POWERBI_WORKSPACE_IDS"
                    ),
                    "candidate_count": len(candidates),
                    "truncated": truncated,
                    "candidates": candidates,
                }
                continue
            if kind == "powerbi_content":
                if powerbi is None:
                    raise SecurityError(
                        "Power BI discovery client is unavailable"
                    )
                candidates = []
                truncated = False
                definitions_by_kind = (
                    (
                        "report",
                        "reports",
                        settings.powerbi_report_ids,
                        "M365_ALLOWED_POWERBI_REPORT_IDS",
                    ),
                    (
                        "dataset",
                        "datasets",
                        settings.powerbi_dataset_ids,
                        "M365_ALLOWED_POWERBI_DATASET_IDS",
                    ),
                    (
                        "dashboard",
                        "dashboards",
                        settings.powerbi_dashboard_ids,
                        "M365_ALLOWED_POWERBI_DASHBOARD_IDS",
                    ),
                )
                for workspace_id in sorted(
                    settings.powerbi_workspace_ids
                ):
                    for resource_type, path, allowlist, variable in (
                        definitions_by_kind
                    ):
                        data = await powerbi.request_json(
                            "GET",
                            f"/groups/{workspace_id}/{path}",
                        )
                        values = data.get("value", [])
                        if not isinstance(values, list):
                            raise SecurityError(
                                "Power BI returned an invalid discovery shape"
                            )
                        if len(values) > settings.max_items:
                            truncated = True
                        for value in values[: settings.max_items]:
                            if not isinstance(value, dict):
                                continue
                            identifier = value.get("id")
                            if not isinstance(identifier, str):
                                continue
                            candidates.append(
                                {
                                    "id": identifier,
                                    "type": resource_type,
                                    "workspace_id": workspace_id,
                                    "display_name": clean_external_text(
                                        value.get("name"),
                                        500,
                                    ),
                                    "currently_allowlisted": (
                                        identifier.lower() in allowlist
                                    ),
                                    "policy_variable": variable,
                                }
                            )
                candidates.sort(
                    key=lambda item: (
                        str(item["workspace_id"]),
                        str(item["type"]),
                        str(item["display_name"]).lower(),
                    )
                )
                resources[kind] = {
                    "candidate_count": len(candidates),
                    "truncated": truncated,
                    "candidates": candidates,
                }
                continue
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
        if owned_powerbi is not None:
            await owned_powerbi.close()

    return {
        "schema_version": "1.0",
        "read_only": True,
        "mcp_tool_exposed": False,
        "policy_changed": False,
        "selection_required": True,
        "untrusted_metadata": True,
        "requested_scopes": list(discovery_settings.scopes),
        "requested_resources": {
            "graph": list(discovery_settings.scopes),
            "powerbi": sorted(discovery_powerbi_scopes),
        },
        "token_scope_policy": {
            "graph": list(full_graph_scopes),
            "powerbi": list(full_powerbi_scopes),
        },
        "resources": resources,
        "privacy_notice": (
            "This operator-only output contains tenant resource identifiers; "
            "do not commit or paste it into public issues."
        ),
    }
