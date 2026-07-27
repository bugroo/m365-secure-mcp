from __future__ import annotations

import pytest

from m365_secure_mcp.config import KNOWN_WRITE_ACTIONS, Settings
from m365_secure_mcp.contract_manifest import AuthorizationMode
from m365_secure_mcp.permissions import READ_TOOL_PERMISSIONS
from m365_secure_mcp.server import WRITE_TOOL_ACTIONS, create_server

from .conftest import CLIENT_ID, TENANT_ID, USER_ID
from .governance_helpers import write_signed_governance

APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
CONDITIONAL_ACCESS_POLICY_ID = "66666666-6666-4666-8666-666666666666"
RESOURCE_ID = "77777777-7777-4777-8777-777777777777"
EDISCOVERY_CASE_ID = "88888888-8888-4888-8888-888888888888"
RETENTION_LABEL_ID = "99999999-9999-4999-8999-999999999999"


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
async def test_minimal_server_exposes_only_common_read_tools() -> None:
    server = create_server(make_settings())
    names = {tool.name for tool in await server.list_tools()}
    assert names == {"m365_get_security_posture", "m365_get_my_profile"}


@pytest.mark.asyncio
async def test_read_modules_control_tool_discovery() -> None:
    server = create_server(
        make_settings(
            modules="profile,mail,planner",
            allowed_plan_ids="plan-1",
        )
    )
    names = {tool.name for tool in await server.list_tools()}
    assert "m365_search_mail" in names
    assert "m365_get_mail_message" in names
    assert "m365_list_planner_tasks" in names
    assert "m365_create_planner_task" not in names
    assert "m365_list_calendar" not in names


@pytest.mark.asyncio
async def test_write_actions_control_tool_discovery() -> None:
    server = create_server(
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="mail.create_draft",
            allowed_recipient_domains="example.com",
        )
    )
    names = {tool.name for tool in await server.list_tools()}
    assert "m365_create_mail_draft" in names
    assert "m365_send_mail_draft" not in names
    assert "m365_create_calendar_event" not in names
    assert "m365_create_planner_task" not in names


@pytest.mark.asyncio
async def test_governed_t1_tool_has_no_endpoint_or_approval_argument(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
    )
    server = create_server(
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="entra.user.operational_profile.update",
            allowed_target_user_ids=RESOURCE_ID,
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    tool = next(
        item
        for item in await server.list_tools()
        if item.name == "m365_update_entra_user_operational_profile"
    )
    params_schema = tool.inputSchema["properties"]["params"]
    schema_name = params_schema["$ref"].removeprefix("#/$defs/")
    fields = set(tool.inputSchema["$defs"][schema_name]["properties"])
    assert fields == {
        "user_id",
        "department",
        "job_title",
        "office_location",
        "idempotency_key",
    }
    assert fields.isdisjoint(
        {"endpoint", "method", "approved", "approval", "tenant_id"}
    )


@pytest.mark.asyncio
async def test_assurance_tool_is_static_read_only_and_argument_free(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
    )
    server = create_server(
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_identity_governance_posture",
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    tool = next(
        item
        for item in await server.list_tools()
        if item.name == "m365_get_entra_identity_governance_posture"
    )
    annotations = tool.annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True
    assert annotations.destructiveHint is False
    params_schema = tool.inputSchema["properties"]["params"]
    schema_name = params_schema["$ref"].removeprefix("#/$defs/")
    fields = set(tool.inputSchema["$defs"][schema_name]["properties"])
    assert fields == {"response_format"}
    assert fields.isdisjoint(
        {"endpoint", "method", "url", "approved", "tenant_id"}
    )


@pytest.mark.asyncio
async def test_permission_drift_tool_accepts_no_target_or_graph_arguments(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
        service_principal_id=SERVICE_PRINCIPAL_ID,
    )
    server = create_server(
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_permission_grant_drift",
            allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    tool = next(
        item
        for item in await server.list_tools()
        if item.name == "m365_get_entra_permission_grant_drift"
    )
    annotations = tool.annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True
    assert annotations.destructiveHint is False
    params_schema = tool.inputSchema["properties"]["params"]
    schema_name = params_schema["$ref"].removeprefix("#/$defs/")
    fields = set(tool.inputSchema["$defs"][schema_name]["properties"])
    assert fields == {"response_format"}
    assert fields.isdisjoint(
        {
            "service_principal_id",
            "endpoint",
            "method",
            "filter",
            "permission",
            "consent",
        }
    )


@pytest.mark.asyncio
async def test_app_credential_posture_accepts_no_target_or_graph_arguments(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
        application_id=APPLICATION_ID,
    )
    server = create_server(
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_app_credential_posture",
            allowed_application_ids=APPLICATION_ID,
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    tool = next(
        item
        for item in await server.list_tools()
        if item.name == "m365_get_entra_app_credential_posture"
    )
    annotations = tool.annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True
    assert annotations.destructiveHint is False
    params_schema = tool.inputSchema["properties"]["params"]
    schema_name = params_schema["$ref"].removeprefix("#/$defs/")
    fields = set(tool.inputSchema["$defs"][schema_name]["properties"])
    assert fields == {"response_format"}
    assert fields.isdisjoint(
        {
            "application_id",
            "endpoint",
            "method",
            "select",
            "credential",
            "secret",
        }
    )


@pytest.mark.asyncio
async def test_workload_readiness_is_static_read_only_and_argument_free(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
        application_id=APPLICATION_ID,
        service_principal_id=SERVICE_PRINCIPAL_ID,
        enable_workload_identity_readiness=True,
    )
    server = create_server(
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_workload_identity_readiness",
            allowed_application_ids=APPLICATION_ID,
            allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    tool = next(
        item
        for item in await server.list_tools()
        if item.name == "m365_get_entra_workload_identity_readiness"
    )
    annotations = tool.annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True
    assert annotations.destructiveHint is False
    assert annotations.idempotentHint is True
    params_schema = tool.inputSchema["properties"]["params"]
    schema_name = params_schema["$ref"].removeprefix("#/$defs/")
    fields = set(tool.inputSchema["$defs"][schema_name]["properties"])
    assert fields == {"response_format"}
    assert fields.isdisjoint(
        {
            "application_id",
            "service_principal_id",
            "endpoint",
            "method",
            "tenant_id",
            "approved",
        }
    )


@pytest.mark.asyncio
async def test_catalog_is_broad_and_module_scoped() -> None:
    server = create_server(
        make_settings(
            modules=(
                "profile,mail,calendar,files,sites,contacts,todo,planner,teams,"
                "directory,groups,organization,onenote,excel,people,presence,"
                "security,audit,intune,service_health,entra_apps,governance,"
                "licensing,users_admin,directory_devices,windows365,"
                "word,powerpoint,excel_workbook,onenote_content,powerbi,"
                "compliance"
            ),
            allowed_site_ids="tenant.sharepoint.com,site-id,web-id",
            allowed_sharepoint_hosts="tenant.sharepoint.com",
            allowed_team_ids="team-1",
            allowed_chat_ids="chat-1",
            allowed_group_ids="group-1",
            allowed_plan_ids="plan-1",
            allowed_target_user_ids=RESOURCE_ID,
            allowed_device_ids=RESOURCE_ID,
            allowed_cloudpc_ids=RESOURCE_ID,
            allowed_drive_ids="drive-1",
            allowed_word_item_ids="word-1",
            allowed_powerpoint_item_ids="powerpoint-1",
            allowed_excel_item_ids="excel-1",
            allowed_onenote_page_ids="page-1",
            allowed_powerbi_workspace_ids=RESOURCE_ID,
            allowed_powerbi_report_ids=RESOURCE_ID,
            allowed_powerbi_dataset_ids=RESOURCE_ID,
            allowed_powerbi_dashboard_ids=RESOURCE_ID,
            allowed_application_ids=APPLICATION_ID,
            allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
            allowed_ediscovery_case_ids=EDISCOVERY_CASE_ID,
            allowed_retention_label_ids=RETENTION_LABEL_ID,
            privileged_modules_enabled=True,
        )
    )
    names = {tool.name for tool in await server.list_tools()}
    assert len(names) == 97
    assert {
        "m365_list_users",
        "m365_list_group_members",
        "m365_list_onenote_pages",
        "m365_list_workbook_tables",
        "m365_list_security_incidents",
        "m365_list_managed_devices",
        "m365_list_service_health",
        "m365_list_allowed_applications",
        "m365_list_service_principal_app_role_assignments",
        "m365_list_conditional_access_policies",
        "m365_list_directory_role_assignments",
        "m365_list_subscribed_skus",
        "m365_list_domains",
        "m365_list_allowed_users",
        "m365_list_allowed_directory_devices",
        "m365_list_allowed_cloudpcs",
        "m365_get_word_document_text",
        "m365_get_powerpoint_presentation_text",
        "m365_get_workbook_range",
        "m365_get_onenote_page_text",
        "m365_list_allowed_powerbi_workspaces",
        "m365_list_allowed_ediscovery_cases",
        "m365_get_retention_label",
    } <= names


@pytest.mark.asyncio
async def test_explicit_tool_allowlist_reduces_enabled_module_surface() -> None:
    server = create_server(
        make_settings(
            modules="profile,directory",
            enabled_tools="m365_list_users",
        )
    )
    names = {tool.name for tool in await server.list_tools()}
    assert names == {"m365_get_security_posture", "m365_list_users"}


def test_every_configured_write_action_has_an_exposed_tool_contract() -> None:
    assert frozenset(WRITE_TOOL_ACTIONS.values()) == KNOWN_WRITE_ACTIONS


@pytest.mark.asyncio
async def test_all_write_actions_are_independently_discoverable(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
        authorization_mode=AuthorizationMode.STANDING_POLICY,
    )
    server = create_server(
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions=",".join(sorted(KNOWN_WRITE_ACTIONS)),
            allowed_recipient_domains="example.com",
            allowed_team_ids="team-1",
            allowed_chat_ids="chat-1",
            allowed_plan_ids="plan-1",
            allowed_target_user_ids=RESOURCE_ID,
            allowed_group_ids=RESOURCE_ID,
            allowed_managed_device_ids=RESOURCE_ID,
            allowed_cloudpc_ids=RESOURCE_ID,
            allowed_drive_ids="drive-1",
            allowed_word_item_ids="word-1",
            allowed_powerpoint_item_ids="powerpoint-1",
            allowed_excel_item_ids="excel-1",
            allowed_onenote_page_ids="page-1",
            allowed_powerbi_workspace_ids=RESOURCE_ID,
            allowed_powerbi_report_ids=RESOURCE_ID,
            allowed_powerbi_dataset_ids=RESOURCE_ID,
            allowed_application_ids=APPLICATION_ID,
            allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
            allowed_conditional_access_policy_ids=(
                CONDITIONAL_ACCESS_POLICY_ID
            ),
            privileged_writes_enabled=True,
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    names = {tool.name for tool in await server.list_tools()}
    assert len(names) == len(WRITE_TOOL_ACTIONS) + 3
    assert set(WRITE_TOOL_ACTIONS) <= names
    assert "m365_get_write_operation" in names
    assert not any(
        forbidden in name
        for name in names
        for forbidden in (
            "grant_permission",
            "admin_consent",
            "assign_role",
            "app_role_assignment",
            "oauth_grant",
            "delete",
        )
    )


@pytest.mark.asyncio
async def test_update_tools_are_annotated_as_destructive_and_idempotent() -> None:
    server = create_server(
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions=(
                "calendar.update_event,todo.update_task,planner.update_task,"
                "planner.update_task_details,entra.update_application,"
                "entra.update_service_principal,"
                "governance.update_conditional_access_policy"
            ),
            allowed_plan_ids="plan-1",
            allowed_application_ids=APPLICATION_ID,
            allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
            allowed_conditional_access_policy_ids=(
                CONDITIONAL_ACCESS_POLICY_ID
            ),
            privileged_writes_enabled=True,
        )
    )
    tools = {tool.name: tool for tool in await server.list_tools()}
    for name in (
        "m365_update_calendar_event",
        "m365_update_todo_task",
        "m365_update_planner_task",
        "m365_update_planner_task_details",
        "m365_update_entra_application",
        "m365_update_entra_service_principal",
        "m365_update_conditional_access_policy",
    ):
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is False
        assert annotations.destructiveHint is True
        assert annotations.idempotentHint is True


def test_out_of_profile_tool_filter_fails_startup() -> None:
    with pytest.raises(ValueError, match="outside the active profile"):
        create_server(
            make_settings(
                enabled_tools="m365_list_security_incidents",
            )
        )


@pytest.mark.asyncio
async def test_every_tool_advertises_the_versioned_result_schema() -> None:
    server = create_server(
        make_settings(
            modules="profile,directory",
        )
    )
    tools = await server.list_tools()
    assert tools
    for tool in tools:
        assert tool.outputSchema is not None
        properties = tool.outputSchema["properties"]
        assert properties["schema_version"]["const"] == "1.0"
        assert {"ok", "tool", "operation_id", "error", "retry", "evidence"} <= set(
            properties
        )


@pytest.mark.asyncio
async def test_every_read_graph_tool_has_an_exact_permission_contract(
    tmp_path,
) -> None:
    governance_policy, governance_key = write_signed_governance(
        tmp_path,
        tenant_id=TENANT_ID,
        user_id=RESOURCE_ID,
    )
    server = create_server(
        make_settings(
            modules=(
                "profile,mail,calendar,files,sites,contacts,todo,planner,teams,"
                "directory,groups,organization,onenote,excel,people,presence,"
                "security,audit,intune,service_health,entra_apps,governance,"
                "assurance,"
                "licensing,users_admin,directory_devices,windows365,"
                "word,powerpoint,excel_workbook,onenote_content,powerbi,"
                "compliance"
            ),
            allowed_site_ids="tenant.sharepoint.com,site-id,web-id",
            allowed_sharepoint_hosts="tenant.sharepoint.com",
            allowed_team_ids="team-1",
            allowed_chat_ids="chat-1",
            allowed_group_ids="group-1",
            allowed_plan_ids="plan-1",
            allowed_target_user_ids=RESOURCE_ID,
            allowed_device_ids=RESOURCE_ID,
            allowed_cloudpc_ids=RESOURCE_ID,
            allowed_drive_ids="drive-1",
            allowed_word_item_ids="word-1",
            allowed_powerpoint_item_ids="powerpoint-1",
            allowed_excel_item_ids="excel-1",
            allowed_onenote_page_ids="page-1",
            allowed_powerbi_workspace_ids=RESOURCE_ID,
            allowed_powerbi_report_ids=RESOURCE_ID,
            allowed_powerbi_dataset_ids=RESOURCE_ID,
            allowed_powerbi_dashboard_ids=RESOURCE_ID,
            allowed_application_ids=APPLICATION_ID,
            allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
            allowed_ediscovery_case_ids=EDISCOVERY_CASE_ID,
            allowed_retention_label_ids=RETENTION_LABEL_ID,
            privileged_modules_enabled=True,
            governance_policy_path=governance_policy,
            governance_public_key_path=governance_key,
        )
    )
    graph_tools = {
        tool.name
        for tool in await server.list_tools()
        if tool.name != "m365_get_security_posture"
    }
    assert graph_tools == set(READ_TOOL_PERMISSIONS)
