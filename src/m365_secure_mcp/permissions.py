"""Auditable tool-to-permission contracts for delegated Microsoft Graph access."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


@dataclass(frozen=True)
class ReadToolPermission:
    """One fixed read tool, its owning module, and least-privileged scopes."""

    module: str
    scopes: frozenset[str]


def _register(
    target: dict[str, ReadToolPermission],
    *,
    module: str,
    scopes: frozenset[str],
    tools: tuple[str, ...],
) -> None:
    for tool in tools:
        if tool in target:
            raise RuntimeError(f"duplicate read-tool permission contract: {tool}")
        target[tool] = ReadToolPermission(module=module, scopes=scopes)


_permissions: dict[str, ReadToolPermission] = {}

_register(
    _permissions,
    module="profile",
    scopes=frozenset({"User.Read"}),
    tools=("m365_get_my_profile",),
)
_register(
    _permissions,
    module="mail",
    scopes=frozenset({"Mail.Read"}),
    tools=(
        "m365_search_mail",
        "m365_get_mail_message",
        "m365_list_mail_folders",
        "m365_list_mail_attachment_metadata",
    ),
)
_register(
    _permissions,
    module="calendar",
    scopes=frozenset({"Calendars.Read"}),
    tools=(
        "m365_list_calendar",
        "m365_find_schedule",
        "m365_list_calendars",
        "m365_get_calendar_event",
    ),
)
_register(
    _permissions,
    module="files",
    scopes=frozenset({"Files.Read"}),
    tools=(
        "m365_search_files",
        "m365_get_file_metadata",
        "m365_list_onedrive_root",
        "m365_list_recent_files",
        "m365_list_shared_files",
        "m365_list_file_children",
    ),
)
_register(
    _permissions,
    module="sites",
    scopes=frozenset({"Sites.Selected"}),
    tools=(
        "m365_list_allowed_sites",
        "m365_list_site_lists",
        "m365_list_site_list_items",
        "m365_list_site_drives",
        "m365_list_site_pages",
    ),
)
_register(
    _permissions,
    module="contacts",
    scopes=frozenset({"Contacts.Read"}),
    tools=("m365_search_contacts", "m365_list_contact_folders"),
)
_register(
    _permissions,
    module="todo",
    scopes=frozenset({"Tasks.Read"}),
    tools=(
        "m365_list_todo_lists",
        "m365_list_todo_tasks",
        "m365_get_todo_task",
    ),
)
_register(
    _permissions,
    module="planner",
    scopes=frozenset({"Tasks.Read"}),
    tools=(
        "m365_list_allowed_plans",
        "m365_list_planner_tasks",
        "m365_list_planner_buckets",
        "m365_get_planner_task",
        "m365_list_my_planner_tasks",
    ),
)

# Teams deliberately uses per-tool scopes. A channel-message permission does
# not authorize team metadata, channel metadata, or channel membership.
_register(
    _permissions,
    module="teams",
    scopes=frozenset({"Team.ReadBasic.All"}),
    tools=("m365_get_team",),
)
_register(
    _permissions,
    module="teams",
    scopes=frozenset({"Channel.ReadBasic.All"}),
    tools=("m365_list_team_channels",),
)
_register(
    _permissions,
    module="teams",
    scopes=frozenset({"ChannelMember.Read.All"}),
    tools=("m365_list_channel_members",),
)
_register(
    _permissions,
    module="teams",
    scopes=frozenset({"ChannelMessage.Read.All"}),
    tools=("m365_list_channel_messages",),
)
_register(
    _permissions,
    module="teams",
    scopes=frozenset({"Chat.ReadBasic"}),
    tools=("m365_list_allowed_chats",),
)
_register(
    _permissions,
    module="teams",
    scopes=frozenset({"Chat.Read"}),
    tools=("m365_list_chat_messages",),
)

_register(
    _permissions,
    module="directory",
    scopes=frozenset({"User.ReadBasic.All"}),
    tools=("m365_list_users", "m365_get_user"),
)
_register(
    _permissions,
    module="groups",
    scopes=frozenset({"GroupMember.Read.All"}),
    tools=(
        "m365_get_group",
        "m365_list_group_members",
        "m365_list_group_owners",
    ),
)
_register(
    _permissions,
    module="organization",
    scopes=frozenset({"Organization.Read.All"}),
    tools=("m365_get_organization",),
)
_register(
    _permissions,
    module="onenote",
    scopes=frozenset({"Notes.Read"}),
    tools=(
        "m365_list_onenote_notebooks",
        "m365_list_onenote_sections",
        "m365_list_onenote_pages",
    ),
)
_register(
    _permissions,
    module="excel",
    scopes=frozenset({"Files.Read"}),
    tools=("m365_list_workbook_worksheets", "m365_list_workbook_tables"),
)
_register(
    _permissions,
    module="people",
    scopes=frozenset({"People.Read"}),
    tools=("m365_list_relevant_people",),
)
_register(
    _permissions,
    module="presence",
    scopes=frozenset({"Presence.Read"}),
    tools=("m365_get_my_presence",),
)
_register(
    _permissions,
    module="security",
    scopes=frozenset({"SecurityIncident.Read.All"}),
    tools=("m365_list_security_incidents",),
)
_register(
    _permissions,
    module="security",
    scopes=frozenset({"SecurityAlert.Read.All"}),
    tools=("m365_list_security_alerts",),
)
_register(
    _permissions,
    module="audit",
    scopes=frozenset({"AuditLog.Read.All"}),
    tools=("m365_list_signins", "m365_list_directory_audits"),
)
_register(
    _permissions,
    module="intune",
    scopes=frozenset({"DeviceManagementManagedDevices.Read.All"}),
    tools=("m365_list_managed_devices",),
)
_register(
    _permissions,
    module="intune",
    scopes=frozenset({"DeviceManagementConfiguration.Read.All"}),
    tools=(
        "m365_list_device_compliance_policies",
        "m365_list_device_configurations",
    ),
)
_register(
    _permissions,
    module="service_health",
    scopes=frozenset({"ServiceHealth.Read.All"}),
    tools=(
        "m365_list_service_health",
        "m365_list_service_issues",
        "m365_list_service_messages",
    ),
)
_register(
    _permissions,
    module="entra_apps",
    scopes=frozenset({"Application.Read.All"}),
    tools=(
        "m365_list_allowed_applications",
        "m365_get_application",
        "m365_list_application_owners",
        "m365_list_allowed_service_principals",
        "m365_get_service_principal",
        "m365_list_service_principal_owners",
        "m365_list_service_principal_app_role_assignments",
    ),
)
_register(
    _permissions,
    module="entra_apps",
    scopes=frozenset({"Directory.Read.All"}),
    tools=("m365_list_service_principal_delegated_grants",),
)
_register(
    _permissions,
    module="governance",
    scopes=frozenset({"Policy.Read.All"}),
    tools=("m365_list_conditional_access_policies",),
)
_register(
    _permissions,
    module="governance",
    scopes=frozenset({"RoleManagement.Read.Directory"}),
    tools=(
        "m365_list_directory_role_definitions",
        "m365_list_directory_role_assignments",
    ),
)
_register(
    _permissions,
    module="governance",
    scopes=frozenset({"AccessReview.Read.All"}),
    tools=("m365_list_access_review_definitions",),
)
_register(
    _permissions,
    module="governance",
    scopes=frozenset({"EntitlementManagement.Read.All"}),
    tools=("m365_list_entitlement_catalogs",),
)
_register(
    _permissions,
    module="licensing",
    scopes=frozenset({"LicenseAssignment.Read.All"}),
    tools=("m365_list_subscribed_skus",),
)
_register(
    _permissions,
    module="licensing",
    scopes=frozenset({"Domain.Read.All"}),
    tools=("m365_list_domains",),
)

READ_TOOL_PERMISSIONS: Final = MappingProxyType(_permissions)
