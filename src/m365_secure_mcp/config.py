"""Validated, fail-closed runtime configuration."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .permissions import READ_TOOL_PERMISSIONS


class Profile(StrEnum):
    """Security profile controlling which tool surface is exposed."""

    READ = "read"
    WRITE = "write"


class Module(StrEnum):
    """Microsoft 365 capability modules."""

    PROFILE = "profile"
    MAIL = "mail"
    CALENDAR = "calendar"
    FILES = "files"
    SITES = "sites"
    CONTACTS = "contacts"
    TODO = "todo"
    PLANNER = "planner"
    TEAMS = "teams"
    DIRECTORY = "directory"
    USERS_ADMIN = "users_admin"
    GROUPS = "groups"
    DIRECTORY_DEVICES = "directory_devices"
    ORGANIZATION = "organization"
    ONENOTE = "onenote"
    ONENOTE_CONTENT = "onenote_content"
    EXCEL = "excel"
    EXCEL_WORKBOOK = "excel_workbook"
    WORD = "word"
    POWERPOINT = "powerpoint"
    POWERBI = "powerbi"
    PEOPLE = "people"
    PRESENCE = "presence"
    SECURITY = "security"
    AUDIT = "audit"
    INTUNE = "intune"
    WINDOWS365 = "windows365"
    SERVICE_HEALTH = "service_health"
    ENTRA_APPS = "entra_apps"
    GOVERNANCE = "governance"
    ASSURANCE = "assurance"
    LICENSING = "licensing"
    COMPLIANCE = "compliance"


READ_SCOPES: dict[Module, frozenset[str]] = {
    module: frozenset(
        scope
        for permission in READ_TOOL_PERMISSIONS.values()
        if permission.module == module.value
        for scope in permission.scopes
    )
    for module in Module
}

PRIVILEGED_MODULES = frozenset(
    {
        Module.ORGANIZATION,
        Module.USERS_ADMIN,
        Module.DIRECTORY_DEVICES,
        Module.SECURITY,
        Module.AUDIT,
        Module.INTUNE,
        Module.SERVICE_HEALTH,
        Module.ENTRA_APPS,
        Module.GOVERNANCE,
        Module.ASSURANCE,
        Module.LICENSING,
        Module.WINDOWS365,
        Module.POWERBI,
        Module.COMPLIANCE,
    }
)

ENTRA_APPLICATION_TOOLS = frozenset(
    {
        "m365_list_allowed_applications",
        "m365_get_application",
        "m365_list_application_owners",
    }
)
ENTRA_SERVICE_PRINCIPAL_TOOLS = frozenset(
    {
        "m365_list_allowed_service_principals",
        "m365_get_service_principal",
        "m365_list_service_principal_owners",
        "m365_list_service_principal_app_role_assignments",
        "m365_list_service_principal_delegated_grants",
    }
)
ASSURANCE_SERVICE_PRINCIPAL_TOOLS = frozenset(
    {
        "m365_get_entra_permission_grant_drift",
        "m365_get_entra_workload_identity_readiness",
    }
)
ASSURANCE_APPLICATION_TOOLS = frozenset(
    {
        "m365_get_entra_app_credential_posture",
        "m365_get_entra_workload_identity_readiness",
    }
)
USERS_ADMIN_TOOLS = frozenset(
    {"m365_list_allowed_users", "m365_get_allowed_user"}
)
DIRECTORY_DEVICE_TOOLS = frozenset(
    {"m365_list_allowed_directory_devices", "m365_get_directory_device"}
)
WINDOWS365_TOOLS = frozenset(
    {"m365_list_allowed_cloudpcs", "m365_get_cloudpc"}
)
EDISCOVERY_TOOLS = frozenset(
    {
        "m365_list_allowed_ediscovery_cases",
        "m365_get_ediscovery_case",
    }
)
RETENTION_LABEL_TOOLS = frozenset(
    {
        "m365_list_allowed_retention_labels",
        "m365_get_retention_label",
    }
)
POWERBI_RESOURCE = "https://analysis.windows.net/powerbi/api"
POWERBI_WORKSPACE_TOOLS = frozenset(
    {
        "m365_list_allowed_powerbi_workspaces",
        "m365_list_powerbi_reports",
        "m365_get_powerbi_report",
        "m365_list_powerbi_datasets",
        "m365_get_powerbi_dataset",
        "m365_list_powerbi_dataset_refreshes",
        "m365_list_powerbi_dataset_datasources",
        "m365_list_powerbi_dashboards",
    }
)
POWERBI_REPORT_TOOLS = frozenset(
    {
        "m365_list_powerbi_reports",
        "m365_get_powerbi_report",
    }
)
POWERBI_DATASET_TOOLS = frozenset(
    {
        "m365_list_powerbi_datasets",
        "m365_get_powerbi_dataset",
        "m365_list_powerbi_dataset_refreshes",
        "m365_list_powerbi_dataset_datasources",
    }
)
POWERBI_DASHBOARD_TOOLS = frozenset({"m365_list_powerbi_dashboards"})

WRITE_ACTION_SCOPES: dict[str, frozenset[str]] = {
    "mail.create_draft": frozenset({"Mail.ReadWrite"}),
    "mail.send_draft": frozenset({"Mail.ReadWrite", "Mail.Send"}),
    "calendar.create_event": frozenset({"Calendars.ReadWrite"}),
    "calendar.update_event": frozenset({"Calendars.ReadWrite"}),
    "contacts.create": frozenset({"Contacts.ReadWrite"}),
    "todo.create_task": frozenset({"Tasks.ReadWrite"}),
    "todo.update_task": frozenset({"Tasks.ReadWrite"}),
    "teams.send_channel_message": frozenset({"ChannelMessage.Send"}),
    "teams.send_chat_message": frozenset({"ChatMessage.Send"}),
    "planner.create_task": frozenset({"Tasks.ReadWrite"}),
    "planner.update_task": frozenset({"Tasks.ReadWrite"}),
    "planner.update_task_details": frozenset({"Tasks.ReadWrite"}),
    "entra.user.operational_profile.update": frozenset(
        {
            "GroupMember.Read.All",
            "RoleManagement.Read.Directory",
            "User.ReadUpdate.All",
        }
    ),
    "users.set_account_enabled": frozenset(
        {"User.EnableDisableAccount.All", "User.Read.All"}
    ),
    "groups.update": frozenset({"Group.ReadWrite.All"}),
    "groups.add_user_member": frozenset({"GroupMember.ReadWrite.All"}),
    "intune.sync_device": frozenset(
        {"DeviceManagementManagedDevices.PrivilegedOperations.All"}
    ),
    "windows365.reboot_cloudpc": frozenset({"CloudPC.ReadWrite.All"}),
    "word.replace_text": frozenset({"Files.ReadWrite"}),
    "powerpoint.replace_text": frozenset({"Files.ReadWrite"}),
    "excel.update_range": frozenset({"Files.ReadWrite"}),
    "onenote.append_page_text": frozenset({"Notes.ReadWrite"}),
    "powerbi.refresh_dataset": frozenset({"Dataset.ReadWrite.All"}),
    "powerbi.rebind_report": frozenset({"Report.ReadWrite.All"}),
    "entra.update_application": frozenset({"Application.ReadWrite.All"}),
    "entra.update_service_principal": frozenset({"Application.ReadWrite.All"}),
    "governance.update_conditional_access_policy": frozenset(
        {"Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"}
    ),
}
WRITE_ACTION_RESOURCES: dict[str, str] = {
    action: (
        "powerbi"
        if action.startswith("powerbi.")
        else "graph"
    )
    for action in WRITE_ACTION_SCOPES
}

KNOWN_WRITE_ACTIONS = frozenset(WRITE_ACTION_SCOPES)
PRIVILEGED_WRITE_ACTIONS = frozenset(
    {
        "entra.update_application",
        "entra.update_service_principal",
        "governance.update_conditional_access_policy",
        "users.set_account_enabled",
        "groups.update",
        "groups.add_user_member",
        "intune.sync_device",
        "windows365.reboot_cloudpc",
        "powerbi.refresh_dataset",
        "powerbi.rebind_report",
    }
)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _uuid_set(value: str, field_name: str) -> frozenset[str]:
    parsed: set[str] = set()
    for raw in _csv(value):
        try:
            parsed.add(str(UUID(raw)))
        except ValueError as exc:
            raise ValueError(f"{field_name} contains an invalid UUID") from exc
    return frozenset(parsed)


class Settings(BaseSettings):
    """Environment-only configuration for the MCP process."""

    model_config = SettingsConfigDict(
        env_prefix="M365_",
        case_sensitive=False,
        extra="ignore",
        str_strip_whitespace=True,
    )

    tenant_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=36, max_length=36)
    deployment_kind: Literal["host", "customer"] = "host"
    profile: Profile = Profile.READ
    modules: str = "profile"

    allowed_user_object_ids: str = ""
    allowed_target_user_ids: str = ""
    allowed_planner_assignee_ids: str = ""
    allowed_upn_domains: str = ""
    allowed_site_ids: str = ""
    allowed_sharepoint_hosts: str = ""
    allowed_team_ids: str = ""
    allowed_chat_ids: str = ""
    allowed_group_ids: str = ""
    allowed_device_ids: str = ""
    allowed_managed_device_ids: str = ""
    allowed_cloudpc_ids: str = ""
    allowed_plan_ids: str = ""
    allowed_drive_ids: str = ""
    allowed_word_item_ids: str = ""
    allowed_powerpoint_item_ids: str = ""
    allowed_excel_item_ids: str = ""
    allowed_onenote_page_ids: str = ""
    allowed_powerbi_workspace_ids: str = ""
    allowed_powerbi_report_ids: str = ""
    allowed_powerbi_dataset_ids: str = ""
    allowed_powerbi_dashboard_ids: str = ""
    allowed_application_ids: str = ""
    allowed_service_principal_ids: str = ""
    allowed_conditional_access_policy_ids: str = ""
    allowed_ediscovery_case_ids: str = ""
    allowed_retention_label_ids: str = ""
    allowed_recipient_domains: str = ""

    auth_flow: Literal["interactive", "device_code"] = "interactive"
    allow_device_code: bool = False
    permission_grant_mode: Literal["admin_preconsented"] = (
        "admin_preconsented"
    )
    reject_unexpected_token_scopes: bool = True
    token_cache_mode: Literal["keyring", "memory"] = "keyring"  # noqa: S105
    keyring_service: str = Field(default="m365-secure-mcp", min_length=3, max_length=100)

    write_enabled: bool = False
    write_actions: str = ""
    privileged_modules_enabled: bool = False
    privileged_writes_enabled: bool = False
    enabled_tools: str = ""
    disabled_tools: str = ""

    graph_timeout_seconds: float = Field(default=20.0, ge=3.0, le=60.0)
    graph_max_retries: int = Field(default=3, ge=0, le=5)
    max_items: int = Field(default=50, ge=1, le=100)
    max_response_bytes: int = Field(default=2_000_000, ge=64_000, le=10_000_000)
    max_tool_characters: int = Field(default=24_000, ge=4_000, le=50_000)
    max_text_file_bytes: int = Field(default=512_000, ge=1_024, le=2_000_000)
    max_office_file_bytes: int = Field(
        default=8_000_000,
        ge=64_000,
        le=25_000_000,
    )
    max_ooxml_members: int = Field(default=3_000, ge=100, le=10_000)
    max_ooxml_expanded_bytes: int = Field(
        default=64_000_000,
        ge=1_000_000,
        le=250_000_000,
    )
    audit_log_path: Path | None = None
    idempotency_db_path: Path | None = None
    governance_policy_path: Path | None = None
    governance_public_key_path: Path | None = None
    approval_broker_dir: Path | None = None
    approval_public_key_path: Path | None = None
    assurance_snapshot_path: Path | None = None
    assurance_max_pages_per_domain: int = Field(default=100, ge=1, le=500)
    assurance_max_records_per_domain: int = Field(
        default=5_000,
        ge=100,
        le=50_000,
    )
    assurance_max_snapshot_bytes: int = Field(
        default=64_000_000,
        ge=1_000_000,
        le=128_000_000,
    )
    assurance_snapshot_ttl_seconds: int = Field(
        default=2_592_000,
        ge=86_400,
        le=31_536_000,
    )
    recovery_capsule_path: Path | None = None
    recovery_capsule_ttl_seconds: int = Field(
        default=604_800,
        ge=3_600,
        le=2_592_000,
    )
    write_rate_limit_per_minute: int = Field(default=10, ge=1, le=120)
    idempotency_pending_seconds: int = Field(default=86_400, ge=300, le=604_800)

    @field_validator("tenant_id", "client_id")
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        parsed = UUID(value)
        if parsed.int == 0:
            raise ValueError("placeholder UUIDs are not allowed")
        return str(parsed)

    @field_validator(
        "allowed_upn_domains",
        "allowed_sharepoint_hosts",
        "allowed_recipient_domains",
    )
    @classmethod
    def validate_domains(cls, value: str) -> str:
        for domain in _csv(value):
            lowered = domain.lower()
            if (
                lowered != domain
                or "/" in domain
                or ":" in domain
                or "@" in domain
                or domain.startswith(".")
                or domain.endswith(".")
            ):
                raise ValueError("domains and hosts must be lowercase bare DNS names")
        return value

    @field_validator(
        "allowed_user_object_ids",
        "allowed_target_user_ids",
        "allowed_planner_assignee_ids",
        "allowed_device_ids",
        "allowed_managed_device_ids",
        "allowed_cloudpc_ids",
        "allowed_application_ids",
        "allowed_service_principal_ids",
        "allowed_conditional_access_policy_ids",
        "allowed_powerbi_workspace_ids",
        "allowed_powerbi_report_ids",
        "allowed_powerbi_dataset_ids",
        "allowed_powerbi_dashboard_ids",
        "allowed_ediscovery_case_ids",
        "allowed_retention_label_ids",
    )
    @classmethod
    def validate_uuid_allowlists(cls, value: str) -> str:
        _uuid_set(value, "UUID allowlist")
        return value

    @model_validator(mode="after")
    def validate_security_posture(self) -> Settings:
        module_names = set(_csv(self.modules))
        enabled_tools = set(_csv(self.enabled_tools))
        disabled_tools = set(_csv(self.disabled_tools))
        unknown_modules = module_names - {module.value for module in Module}
        if unknown_modules:
            raise ValueError(f"unknown M365 modules: {sorted(unknown_modules)}")
        if not module_names:
            raise ValueError("at least one M365 module must be enabled")
        if self.deployment_kind == "customer" and not self.allowed_user_ids:
            raise ValueError(
                "customer deployments require M365_ALLOWED_USER_OBJECT_IDS"
            )
        if Module.SITES.value in module_names and not self.site_ids:
            raise ValueError("sites module requires M365_ALLOWED_SITE_IDS")
        if Module.TEAMS.value in module_names and not self.team_ids:
            raise ValueError("teams module requires M365_ALLOWED_TEAM_IDS")
        if Module.PLANNER.value in module_names and not self.plan_ids:
            raise ValueError("planner module requires M365_ALLOWED_PLAN_IDS")
        if Module.GROUPS.value in module_names and not self.group_ids:
            raise ValueError("groups module requires M365_ALLOWED_GROUP_IDS")
        if (
            Module.USERS_ADMIN.value in module_names
            and not self.target_user_ids
        ):
            raise ValueError(
                "users_admin module requires M365_ALLOWED_TARGET_USER_IDS"
            )
        if (
            Module.DIRECTORY_DEVICES.value in module_names
            and not self.device_ids
        ):
            raise ValueError(
                "directory_devices module requires M365_ALLOWED_DEVICE_IDS"
            )
        if (
            Module.WINDOWS365.value in module_names
            and not self.cloudpc_ids
        ):
            raise ValueError(
                "windows365 module requires M365_ALLOWED_CLOUDPC_IDS"
            )
        if Module.WORD.value in module_names:
            if not self.drive_ids:
                raise ValueError("word module requires M365_ALLOWED_DRIVE_IDS")
            if not self.word_item_ids:
                raise ValueError("word module requires M365_ALLOWED_WORD_ITEM_IDS")
        if Module.POWERPOINT.value in module_names:
            if not self.drive_ids:
                raise ValueError("powerpoint module requires M365_ALLOWED_DRIVE_IDS")
            if not self.powerpoint_item_ids:
                raise ValueError(
                    "powerpoint module requires M365_ALLOWED_POWERPOINT_ITEM_IDS"
                )
        if Module.EXCEL_WORKBOOK.value in module_names:
            if not self.drive_ids:
                raise ValueError(
                    "excel_workbook module requires M365_ALLOWED_DRIVE_IDS"
                )
            if not self.excel_item_ids:
                raise ValueError(
                    "excel_workbook module requires M365_ALLOWED_EXCEL_ITEM_IDS"
                )
        if (
            Module.ONENOTE_CONTENT.value in module_names
            and not self.onenote_page_ids
        ):
            raise ValueError(
                "onenote_content module requires M365_ALLOWED_ONENOTE_PAGE_IDS"
            )
        if Module.POWERBI.value in module_names:
            selected_powerbi_tools = (
                POWERBI_WORKSPACE_TOOLS
                if not enabled_tools
                else POWERBI_WORKSPACE_TOOLS & enabled_tools
            ) - disabled_tools
            if selected_powerbi_tools and not self.powerbi_workspace_ids:
                raise ValueError(
                    "Power BI tools require M365_ALLOWED_POWERBI_WORKSPACE_IDS"
                )
            if (
                selected_powerbi_tools & POWERBI_REPORT_TOOLS
                and not self.powerbi_report_ids
            ):
                raise ValueError(
                    "Power BI report tools require "
                    "M365_ALLOWED_POWERBI_REPORT_IDS"
                )
            if (
                selected_powerbi_tools & POWERBI_DATASET_TOOLS
                and not self.powerbi_dataset_ids
            ):
                raise ValueError(
                    "Power BI dataset tools require "
                    "M365_ALLOWED_POWERBI_DATASET_IDS"
                )
            if (
                selected_powerbi_tools & POWERBI_DASHBOARD_TOOLS
                and not self.powerbi_dashboard_ids
            ):
                raise ValueError(
                    "Power BI dashboard tools require "
                    "M365_ALLOWED_POWERBI_DASHBOARD_IDS"
                )
        if Module.ENTRA_APPS.value in module_names:
            selected_application_tools = (
                ENTRA_APPLICATION_TOOLS
                if not enabled_tools
                else ENTRA_APPLICATION_TOOLS & enabled_tools
            ) - disabled_tools
            selected_service_principal_tools = (
                ENTRA_SERVICE_PRINCIPAL_TOOLS
                if not enabled_tools
                else ENTRA_SERVICE_PRINCIPAL_TOOLS & enabled_tools
            ) - disabled_tools
            if selected_application_tools and not self.application_ids:
                raise ValueError(
                    "Entra application tools require M365_ALLOWED_APPLICATION_IDS"
                )
            if (
                selected_service_principal_tools
                and not self.service_principal_ids
            ):
                raise ValueError(
                    "Entra service-principal tools require "
                    "M365_ALLOWED_SERVICE_PRINCIPAL_IDS"
                )
        if Module.ASSURANCE.value in module_names:
            selected_application_posture_tools = (
                ASSURANCE_APPLICATION_TOOLS
                if not enabled_tools
                else ASSURANCE_APPLICATION_TOOLS & enabled_tools
            ) - disabled_tools
            selected_permission_drift_tools = (
                ASSURANCE_SERVICE_PRINCIPAL_TOOLS
                if not enabled_tools
                else ASSURANCE_SERVICE_PRINCIPAL_TOOLS & enabled_tools
            ) - disabled_tools
            if (
                selected_application_posture_tools
                and not self.application_ids
            ):
                raise ValueError(
                    "Entra application credential posture requires "
                    "M365_ALLOWED_APPLICATION_IDS"
                )
            if (
                selected_permission_drift_tools
                and not self.service_principal_ids
            ):
                raise ValueError(
                    "Entra permission-grant drift requires "
                    "M365_ALLOWED_SERVICE_PRINCIPAL_IDS"
                )
        if Module.COMPLIANCE.value in module_names:
            selected_ediscovery_tools = (
                EDISCOVERY_TOOLS
                if not enabled_tools
                else EDISCOVERY_TOOLS & enabled_tools
            ) - disabled_tools
            selected_retention_tools = (
                RETENTION_LABEL_TOOLS
                if not enabled_tools
                else RETENTION_LABEL_TOOLS & enabled_tools
            ) - disabled_tools
            if selected_ediscovery_tools and not self.ediscovery_case_ids:
                raise ValueError(
                    "eDiscovery tools require "
                    "M365_ALLOWED_EDISCOVERY_CASE_IDS"
                )
            if selected_retention_tools and not self.retention_label_ids:
                raise ValueError(
                    "retention-label tools require "
                    "M365_ALLOWED_RETENTION_LABEL_IDS"
                )
        privileged = {Module(item) for item in module_names} & PRIVILEGED_MODULES
        if privileged and not self.privileged_modules_enabled:
            names = sorted(module.value for module in privileged)
            raise ValueError(
                f"privileged modules require M365_PRIVILEGED_MODULES_ENABLED=true: {names}"
            )

        if self.auth_flow == "device_code" and not self.allow_device_code:
            raise ValueError(
                "device-code flow is blocked; explicitly set M365_ALLOW_DEVICE_CODE=true"
            )

        actions = set(_csv(self.write_actions))
        unknown_actions = actions - KNOWN_WRITE_ACTIONS
        if unknown_actions:
            raise ValueError(f"unknown write actions: {sorted(unknown_actions)}")
        if (self.governance_policy_path is None) != (
            self.governance_public_key_path is None
        ):
            raise ValueError(
                "governance policy and trusted public-key paths must be configured together"
            )
        if (
            self.profile is Profile.READ
            and Module.ASSURANCE.value in module_names
            and self.governance_policy_path is None
        ):
            raise ValueError(
                "assurance posture requires M365_GOVERNANCE_POLICY_PATH and "
                "M365_GOVERNANCE_PUBLIC_KEY_PATH"
            )
        if (
            "entra.user.operational_profile.update" in actions
            and self.governance_policy_path is None
        ):
            raise ValueError(
                "entra.user.operational_profile.update requires "
                "M365_GOVERNANCE_POLICY_PATH and "
                "M365_GOVERNANCE_PUBLIC_KEY_PATH"
            )

        if self.profile is Profile.WRITE:
            if not self.write_enabled:
                raise ValueError("write profile requires M365_WRITE_ENABLED=true")
            if not actions:
                raise ValueError("write profile requires an explicit M365_WRITE_ACTIONS allowlist")
        privileged_actions = actions & PRIVILEGED_WRITE_ACTIONS
        if privileged_actions and not self.privileged_writes_enabled:
            raise ValueError(
                "privileged write actions require "
                "M365_PRIVILEGED_WRITES_ENABLED=true"
            )

        recipient_actions = {
            "mail.create_draft",
            "mail.send_draft",
            "calendar.create_event",
            "contacts.create",
        } & actions
        if recipient_actions and not self.recipient_domains:
            raise ValueError("recipient-bearing writes require M365_ALLOWED_RECIPIENT_DOMAINS")
        planner_actions = {
            "planner.create_task",
            "planner.update_task",
            "planner.update_task_details",
        } & actions
        if planner_actions and not self.plan_ids:
            raise ValueError("Planner write actions require M365_ALLOWED_PLAN_IDS")
        if "teams.send_channel_message" in actions and not self.team_ids:
            raise ValueError("Teams channel writes require M365_ALLOWED_TEAM_IDS")
        if "teams.send_chat_message" in actions and not self.chat_ids:
            raise ValueError("Teams chat writes require M365_ALLOWED_CHAT_IDS")
        if (
            {
                "entra.user.operational_profile.update",
                "users.set_account_enabled",
            }
            & actions
            and not self.target_user_ids
        ):
            raise ValueError(
                "user writes require M365_ALLOWED_TARGET_USER_IDS"
            )
        if (
            {"groups.update", "groups.add_user_member"} & actions
            and not self.group_ids
        ):
            raise ValueError(
                "group writes require M365_ALLOWED_GROUP_IDS"
            )
        if (
            "groups.add_user_member" in actions
            and not self.target_user_ids
        ):
            raise ValueError(
                "group membership writes require "
                "M365_ALLOWED_TARGET_USER_IDS"
            )
        if (
            "intune.sync_device" in actions
            and not self.managed_device_ids
        ):
            raise ValueError(
                "Intune device actions require "
                "M365_ALLOWED_MANAGED_DEVICE_IDS"
            )
        if (
            "windows365.reboot_cloudpc" in actions
            and not self.cloudpc_ids
        ):
            raise ValueError(
                "Windows 365 actions require M365_ALLOWED_CLOUDPC_IDS"
            )
        office_actions = {
            "word.replace_text",
            "powerpoint.replace_text",
            "excel.update_range",
        } & actions
        if office_actions and not self.drive_ids:
            raise ValueError("Office file writes require M365_ALLOWED_DRIVE_IDS")
        if "word.replace_text" in actions and not self.word_item_ids:
            raise ValueError(
                "Word writes require M365_ALLOWED_WORD_ITEM_IDS"
            )
        if (
            "powerpoint.replace_text" in actions
            and not self.powerpoint_item_ids
        ):
            raise ValueError(
                "PowerPoint writes require M365_ALLOWED_POWERPOINT_ITEM_IDS"
            )
        if "excel.update_range" in actions and not self.excel_item_ids:
            raise ValueError(
                "Excel writes require M365_ALLOWED_EXCEL_ITEM_IDS"
            )
        if (
            "onenote.append_page_text" in actions
            and not self.onenote_page_ids
        ):
            raise ValueError(
                "OneNote writes require M365_ALLOWED_ONENOTE_PAGE_IDS"
            )
        powerbi_actions = {
            "powerbi.refresh_dataset",
            "powerbi.rebind_report",
        } & actions
        if powerbi_actions and not self.powerbi_workspace_ids:
            raise ValueError(
                "Power BI writes require M365_ALLOWED_POWERBI_WORKSPACE_IDS"
            )
        if (
            "powerbi.refresh_dataset" in actions
            and not self.powerbi_dataset_ids
        ):
            raise ValueError(
                "Power BI refresh requires M365_ALLOWED_POWERBI_DATASET_IDS"
            )
        if "powerbi.rebind_report" in actions:
            if not self.powerbi_report_ids:
                raise ValueError(
                    "Power BI rebind requires M365_ALLOWED_POWERBI_REPORT_IDS"
                )
            if not self.powerbi_dataset_ids:
                raise ValueError(
                    "Power BI rebind requires M365_ALLOWED_POWERBI_DATASET_IDS"
                )
        if "entra.update_application" in actions and not self.application_ids:
            raise ValueError(
                "Entra application writes require M365_ALLOWED_APPLICATION_IDS"
            )
        if (
            "entra.update_service_principal" in actions
            and not self.service_principal_ids
        ):
            raise ValueError(
                "Entra service-principal writes require "
                "M365_ALLOWED_SERVICE_PRINCIPAL_IDS"
            )
        if (
            "governance.update_conditional_access_policy" in actions
            and not self.conditional_access_policy_ids
        ):
            raise ValueError(
                "Conditional Access writes require "
                "M365_ALLOWED_CONDITIONAL_ACCESS_POLICY_IDS"
            )

        for tool_name in enabled_tools | disabled_tools:
            if not re.fullmatch(r"m365_[a-z0-9_]{3,96}", tool_name):
                raise ValueError("tool allowlists accept only explicit m365_* tool names")
        overlap = enabled_tools & disabled_tools
        if overlap:
            raise ValueError(f"tools cannot be both enabled and disabled: {sorted(overlap)}")
        if (self.approval_broker_dir is None) != (
            self.approval_public_key_path is None
        ):
            raise ValueError(
                "external approval requires both M365_APPROVAL_BROKER_DIR "
                "and M365_APPROVAL_PUBLIC_KEY_PATH"
            )
        if self.approval_broker_dir is not None and self.profile is not Profile.WRITE:
            raise ValueError("external approval broker is valid only in a write process")
        return self

    @property
    def enabled_modules(self) -> frozenset[Module]:
        return frozenset(Module(item) for item in _csv(self.modules))

    @property
    def enabled_write_actions(self) -> frozenset[str]:
        return frozenset(_csv(self.write_actions))

    @property
    def allowed_user_ids(self) -> frozenset[str]:
        return _uuid_set(self.allowed_user_object_ids, "M365_ALLOWED_USER_OBJECT_IDS")

    @property
    def upn_domains(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_upn_domains))

    @property
    def target_user_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_target_user_ids,
            "M365_ALLOWED_TARGET_USER_IDS",
        )

    @property
    def planner_assignee_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_planner_assignee_ids,
            "M365_ALLOWED_PLANNER_ASSIGNEE_IDS",
        )

    @property
    def site_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_site_ids))

    @property
    def sharepoint_hosts(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_sharepoint_hosts))

    @property
    def team_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_team_ids))

    @property
    def chat_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_chat_ids))

    @property
    def group_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_group_ids))

    @property
    def device_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_device_ids,
            "M365_ALLOWED_DEVICE_IDS",
        )

    @property
    def managed_device_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_managed_device_ids,
            "M365_ALLOWED_MANAGED_DEVICE_IDS",
        )

    @property
    def cloudpc_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_cloudpc_ids,
            "M365_ALLOWED_CLOUDPC_IDS",
        )

    @property
    def plan_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_plan_ids))

    @property
    def drive_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_drive_ids))

    @property
    def word_item_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_word_item_ids))

    @property
    def powerpoint_item_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_powerpoint_item_ids))

    @property
    def excel_item_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_excel_item_ids))

    @property
    def onenote_page_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_onenote_page_ids))

    @property
    def powerbi_workspace_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_powerbi_workspace_ids,
            "M365_ALLOWED_POWERBI_WORKSPACE_IDS",
        )

    @property
    def powerbi_report_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_powerbi_report_ids,
            "M365_ALLOWED_POWERBI_REPORT_IDS",
        )

    @property
    def powerbi_dataset_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_powerbi_dataset_ids,
            "M365_ALLOWED_POWERBI_DATASET_IDS",
        )

    @property
    def powerbi_dashboard_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_powerbi_dashboard_ids,
            "M365_ALLOWED_POWERBI_DASHBOARD_IDS",
        )

    @property
    def application_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_application_ids,
            "M365_ALLOWED_APPLICATION_IDS",
        )

    @property
    def service_principal_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_service_principal_ids,
            "M365_ALLOWED_SERVICE_PRINCIPAL_IDS",
        )

    @property
    def conditional_access_policy_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_conditional_access_policy_ids,
            "M365_ALLOWED_CONDITIONAL_ACCESS_POLICY_IDS",
        )

    @property
    def ediscovery_case_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_ediscovery_case_ids,
            "M365_ALLOWED_EDISCOVERY_CASE_IDS",
        )

    @property
    def retention_label_ids(self) -> frozenset[str]:
        return _uuid_set(
            self.allowed_retention_label_ids,
            "M365_ALLOWED_RETENTION_LABEL_IDS",
        )

    @property
    def recipient_domains(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_recipient_domains))

    @property
    def tool_allowlist(self) -> frozenset[str]:
        return frozenset(_csv(self.enabled_tools))

    @property
    def tool_denylist(self) -> frozenset[str]:
        return frozenset(_csv(self.disabled_tools))

    @property
    def scopes(self) -> tuple[str, ...]:
        scopes: set[str] = {"User.Read"}
        if self.profile is Profile.READ:
            selected_tools = {
                name
                for name, permission in READ_TOOL_PERMISSIONS.items()
                if Module(permission.module) in self.enabled_modules
            }
            if self.tool_allowlist:
                selected_tools &= self.tool_allowlist
            selected_tools -= self.tool_denylist
            for tool in selected_tools:
                permission = READ_TOOL_PERMISSIONS[tool]
                if permission.resource == "graph":
                    scopes.update(permission.scopes)
        else:
            for action in self.enabled_write_actions:
                if WRITE_ACTION_RESOURCES[action] == "graph":
                    scopes.update(WRITE_ACTION_SCOPES[action])
        return tuple(sorted(scopes))

    @property
    def powerbi_scopes(self) -> tuple[str, ...]:
        scopes: set[str] = set()
        if self.profile is Profile.READ:
            selected_tools = {
                name
                for name, permission in READ_TOOL_PERMISSIONS.items()
                if (
                    permission.resource == "powerbi"
                    and Module(permission.module) in self.enabled_modules
                )
            }
            if self.tool_allowlist:
                selected_tools &= self.tool_allowlist
            selected_tools -= self.tool_denylist
            for tool in selected_tools:
                scopes.update(READ_TOOL_PERMISSIONS[tool].scopes)
        else:
            for action in self.enabled_write_actions:
                if WRITE_ACTION_RESOURCES[action] == "powerbi":
                    scopes.update(WRITE_ACTION_SCOPES[action])
        return tuple(
            f"{POWERBI_RESOURCE}/{scope}"
            for scope in sorted(scopes)
        )

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def cache_username(self) -> str:
        return self.cache_username_for("graph")

    def cache_username_for(self, resource: str) -> str:
        if resource not in {"graph", "powerbi"}:
            raise ValueError("unsupported token-cache resource")
        return (
            f"{self.tenant_id}:{self.client_id}:"
            f"{self.deployment_kind}:{self.profile.value}:{resource}"
        )

    @property
    def deployment_namespace(self) -> str:
        material = (
            f"{self.tenant_id}:{self.client_id}:"
            f"{self.deployment_kind}:{self.profile.value}"
        ).encode()
        return hashlib.sha256(material).hexdigest()[:16]

    @property
    def effective_audit_log_path(self) -> Path:
        if self.audit_log_path is not None:
            return self.audit_log_path.expanduser()
        return (
            Path.home()
            / "Library"
            / "Logs"
            / "m365-secure-mcp"
            / (
                f"audit-{self.deployment_kind}-{self.profile.value}-"
                f"{self.deployment_namespace}.jsonl"
            )
        )

    @property
    def effective_idempotency_db_path(self) -> Path:
        if self.idempotency_db_path is not None:
            return self.idempotency_db_path.expanduser()
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "m365-secure-mcp"
            / (
                f"idempotency-{self.deployment_kind}-{self.profile.value}-"
                f"{self.deployment_namespace}.sqlite3"
            )
        )

    @property
    def effective_recovery_capsule_path(self) -> Path:
        if self.recovery_capsule_path is not None:
            return self.recovery_capsule_path.expanduser()
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "m365-secure-mcp"
            / (
                f"recovery-{self.deployment_kind}-{self.profile.value}-"
                f"{self.deployment_namespace}.jsonl"
            )
        )

    @property
    def effective_assurance_snapshot_path(self) -> Path:
        if self.assurance_snapshot_path is not None:
            return self.assurance_snapshot_path.expanduser()
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "m365-secure-mcp"
            / (
                f"assurance-{self.deployment_kind}-{self.profile.value}-"
                f"{self.deployment_namespace}.jsonl"
            )
        )

    @property
    def external_approval_configured(self) -> bool:
        return bool(
            self.approval_broker_dir is not None
            and self.approval_public_key_path is not None
        )

    def public_summary(self) -> dict[str, object]:
        """Return a configuration summary that never includes credentials or tokens."""

        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "deployment_kind": self.deployment_kind,
            "profile": self.profile.value,
            "modules": sorted(module.value for module in self.enabled_modules),
            "scopes": list(self.scopes),
            "powerbi_scopes": list(self.powerbi_scopes),
            "permission_grant_mode": self.permission_grant_mode,
            "reject_unexpected_token_scopes": (
                self.reject_unexpected_token_scopes
            ),
            "principal_object_id_allowlist_configured": bool(self.allowed_user_ids),
            "target_user_allowlist_count": len(self.target_user_ids),
            "planner_assignee_allowlist_count": len(
                self.planner_assignee_ids
            ),
            "upn_domain_allowlist": sorted(self.upn_domains),
            "site_allowlist_count": len(self.site_ids),
            "sharepoint_host_allowlist": sorted(self.sharepoint_hosts),
            "team_allowlist_count": len(self.team_ids),
            "chat_allowlist_count": len(self.chat_ids),
            "group_allowlist_count": len(self.group_ids),
            "directory_device_allowlist_count": len(self.device_ids),
            "managed_device_allowlist_count": len(
                self.managed_device_ids
            ),
            "cloudpc_allowlist_count": len(self.cloudpc_ids),
            "planner_plan_allowlist_count": len(self.plan_ids),
            "entra_application_allowlist_count": len(self.application_ids),
            "entra_service_principal_allowlist_count": len(
                self.service_principal_ids
            ),
            "conditional_access_policy_allowlist_count": len(
                self.conditional_access_policy_ids
            ),
            "ediscovery_case_allowlist_count": len(
                self.ediscovery_case_ids
            ),
            "retention_label_allowlist_count": len(
                self.retention_label_ids
            ),
            "privileged_modules_enabled": self.privileged_modules_enabled,
            "privileged_writes_enabled": self.privileged_writes_enabled,
            "explicit_tool_allowlist": sorted(self.tool_allowlist),
            "explicit_tool_denylist": sorted(self.tool_denylist),
            "write_enabled": self.write_enabled,
            "write_actions": sorted(self.enabled_write_actions),
            "signed_governance_policy_configured": bool(
                self.governance_policy_path
                and self.governance_public_key_path
            ),
            "external_approval_broker_configured": (
                self.external_approval_configured
            ),
            "assurance_snapshot_local_encryption": (
                "ephemeral"
                if self.token_cache_mode == "memory"  # noqa: S105
                else "os_keychain"
            ),
            "assurance_max_pages_per_domain": (
                self.assurance_max_pages_per_domain
            ),
            "assurance_max_records_per_domain": (
                self.assurance_max_records_per_domain
            ),
            "assurance_max_snapshot_bytes": self.assurance_max_snapshot_bytes,
            "token_cache_mode": self.token_cache_mode,
            "auth_flow": self.auth_flow,
            "write_rate_limit_per_minute": self.write_rate_limit_per_minute,
        }

    def agent_summary(self) -> dict[str, object]:
        """Return policy posture without tenant, client, domain, or resource values."""

        return {
            "tenant_id_configured": True,
            "client_id_configured": True,
            "deployment_kind": self.deployment_kind,
            "profile": self.profile.value,
            "modules": sorted(module.value for module in self.enabled_modules),
            "scopes": list(self.scopes),
            "powerbi_scope_count": len(self.powerbi_scopes),
            "permission_grant_mode": self.permission_grant_mode,
            "reject_unexpected_token_scopes": (
                self.reject_unexpected_token_scopes
            ),
            "principal_object_id_allowlist_configured": bool(
                self.allowed_user_ids
            ),
            "target_user_allowlist_count": len(self.target_user_ids),
            "planner_assignee_allowlist_count": len(
                self.planner_assignee_ids
            ),
            "upn_domain_allowlist_count": len(self.upn_domains),
            "site_allowlist_count": len(self.site_ids),
            "sharepoint_host_allowlist_count": len(self.sharepoint_hosts),
            "team_allowlist_count": len(self.team_ids),
            "chat_allowlist_count": len(self.chat_ids),
            "group_allowlist_count": len(self.group_ids),
            "directory_device_allowlist_count": len(self.device_ids),
            "managed_device_allowlist_count": len(
                self.managed_device_ids
            ),
            "cloudpc_allowlist_count": len(self.cloudpc_ids),
            "planner_plan_allowlist_count": len(self.plan_ids),
            "drive_allowlist_count": len(self.drive_ids),
            "word_item_allowlist_count": len(self.word_item_ids),
            "powerpoint_item_allowlist_count": len(
                self.powerpoint_item_ids
            ),
            "excel_item_allowlist_count": len(self.excel_item_ids),
            "onenote_page_allowlist_count": len(self.onenote_page_ids),
            "powerbi_workspace_allowlist_count": len(
                self.powerbi_workspace_ids
            ),
            "powerbi_report_allowlist_count": len(self.powerbi_report_ids),
            "powerbi_dataset_allowlist_count": len(
                self.powerbi_dataset_ids
            ),
            "powerbi_dashboard_allowlist_count": len(
                self.powerbi_dashboard_ids
            ),
            "entra_application_allowlist_count": len(self.application_ids),
            "entra_service_principal_allowlist_count": len(
                self.service_principal_ids
            ),
            "conditional_access_policy_allowlist_count": len(
                self.conditional_access_policy_ids
            ),
            "ediscovery_case_allowlist_count": len(
                self.ediscovery_case_ids
            ),
            "retention_label_allowlist_count": len(
                self.retention_label_ids
            ),
            "privileged_modules_enabled": self.privileged_modules_enabled,
            "privileged_writes_enabled": self.privileged_writes_enabled,
            "explicit_tool_allowlist_count": len(self.tool_allowlist),
            "explicit_tool_denylist_count": len(self.tool_denylist),
            "write_enabled": self.write_enabled,
            "write_action_count": len(self.enabled_write_actions),
            "signed_governance_policy_configured": bool(
                self.governance_policy_path
                and self.governance_public_key_path
            ),
            "external_approval_broker_configured": (
                self.external_approval_configured
            ),
            "assurance_snapshot_local_encryption": (
                "ephemeral"
                if self.token_cache_mode == "memory"  # noqa: S105
                else "os_keychain"
            ),
            "assurance_max_pages_per_domain": (
                self.assurance_max_pages_per_domain
            ),
            "assurance_max_records_per_domain": (
                self.assurance_max_records_per_domain
            ),
            "assurance_max_snapshot_bytes": self.assurance_max_snapshot_bytes,
            "token_cache_mode": self.token_cache_mode,
            "auth_flow": self.auth_flow,
            "write_rate_limit_per_minute": self.write_rate_limit_per_minute,
        }

    @property
    def policy_digest(self) -> str:
        """Return a stable digest of the effective, secret-free local policy."""

        canonical = json.dumps(
            self._policy_material(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"

    def _policy_material(self) -> dict[str, object]:
        """Return complete policy material for hashing, never for direct output."""

        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "deployment_kind": self.deployment_kind,
            "profile": self.profile.value,
            "modules": sorted(module.value for module in self.enabled_modules),
            "scopes": list(self.scopes),
            "powerbi_scopes": list(self.powerbi_scopes),
            "allowed_user_ids": sorted(self.allowed_user_ids),
            "target_user_ids": sorted(self.target_user_ids),
            "planner_assignee_ids": sorted(self.planner_assignee_ids),
            "upn_domains": sorted(self.upn_domains),
            "site_ids": sorted(self.site_ids),
            "sharepoint_hosts": sorted(self.sharepoint_hosts),
            "team_ids": sorted(self.team_ids),
            "chat_ids": sorted(self.chat_ids),
            "group_ids": sorted(self.group_ids),
            "device_ids": sorted(self.device_ids),
            "managed_device_ids": sorted(self.managed_device_ids),
            "cloudpc_ids": sorted(self.cloudpc_ids),
            "plan_ids": sorted(self.plan_ids),
            "drive_ids": sorted(self.drive_ids),
            "word_item_ids": sorted(self.word_item_ids),
            "powerpoint_item_ids": sorted(self.powerpoint_item_ids),
            "excel_item_ids": sorted(self.excel_item_ids),
            "onenote_page_ids": sorted(self.onenote_page_ids),
            "powerbi_workspace_ids": sorted(self.powerbi_workspace_ids),
            "powerbi_report_ids": sorted(self.powerbi_report_ids),
            "powerbi_dataset_ids": sorted(self.powerbi_dataset_ids),
            "powerbi_dashboard_ids": sorted(self.powerbi_dashboard_ids),
            "application_ids": sorted(self.application_ids),
            "service_principal_ids": sorted(self.service_principal_ids),
            "conditional_access_policy_ids": sorted(
                self.conditional_access_policy_ids
            ),
            "ediscovery_case_ids": sorted(self.ediscovery_case_ids),
            "retention_label_ids": sorted(self.retention_label_ids),
            "recipient_domains": sorted(self.recipient_domains),
            "auth_flow": self.auth_flow,
            "allow_device_code": self.allow_device_code,
            "permission_grant_mode": self.permission_grant_mode,
            "reject_unexpected_token_scopes": (
                self.reject_unexpected_token_scopes
            ),
            "token_cache_mode": self.token_cache_mode,
            "write_enabled": self.write_enabled,
            "write_actions": sorted(self.enabled_write_actions),
            "privileged_modules_enabled": self.privileged_modules_enabled,
            "privileged_writes_enabled": self.privileged_writes_enabled,
            "external_approval_broker_configured": (
                self.external_approval_configured
            ),
            "tool_allowlist": sorted(self.tool_allowlist),
            "tool_denylist": sorted(self.tool_denylist),
            "graph_timeout_seconds": self.graph_timeout_seconds,
            "graph_max_retries": self.graph_max_retries,
            "max_items": self.max_items,
            "max_response_bytes": self.max_response_bytes,
            "max_tool_characters": self.max_tool_characters,
            "max_text_file_bytes": self.max_text_file_bytes,
            "max_office_file_bytes": self.max_office_file_bytes,
            "max_ooxml_members": self.max_ooxml_members,
            "max_ooxml_expanded_bytes": self.max_ooxml_expanded_bytes,
            "write_rate_limit_per_minute": self.write_rate_limit_per_minute,
            "idempotency_pending_seconds": self.idempotency_pending_seconds,
            "audit_log_path": str(self.effective_audit_log_path),
            "idempotency_db_path": str(self.effective_idempotency_db_path),
            "governance_policy_path": (
                str(self.governance_policy_path.expanduser())
                if self.governance_policy_path is not None
                else None
            ),
            "governance_public_key_path": (
                str(self.governance_public_key_path.expanduser())
                if self.governance_public_key_path is not None
                else None
            ),
            "approval_broker_dir": (
                str(self.approval_broker_dir.expanduser())
                if self.approval_broker_dir is not None
                else None
            ),
            "approval_public_key_path": (
                str(self.approval_public_key_path.expanduser())
                if self.approval_public_key_path is not None
                else None
            ),
            "assurance_snapshot_path": str(
                self.effective_assurance_snapshot_path
            ),
            "assurance_max_pages_per_domain": (
                self.assurance_max_pages_per_domain
            ),
            "assurance_max_records_per_domain": (
                self.assurance_max_records_per_domain
            ),
            "assurance_max_snapshot_bytes": self.assurance_max_snapshot_bytes,
            "assurance_snapshot_ttl_seconds": (
                self.assurance_snapshot_ttl_seconds
            ),
            "recovery_capsule_path": str(self.effective_recovery_capsule_path),
            "recovery_capsule_ttl_seconds": self.recovery_capsule_ttl_seconds,
        }

    def permission_explanation(self) -> dict[str, object]:
        """Explain exactly why each effective delegated scope is requested."""

        module_names = sorted(module.value for module in self.enabled_modules)
        modules = [
            {
                "module": module_name,
                "resources": {
                    resource: sorted(
                        {
                            scope
                            for tool, permission in (
                                READ_TOOL_PERMISSIONS.items()
                            )
                            if permission.module == module_name
                            and permission.resource == resource
                            and (
                                not self.tool_allowlist
                                or tool in self.tool_allowlist
                            )
                            and tool not in self.tool_denylist
                            for scope in permission.scopes
                        }
                    )
                    for resource in ("graph", "powerbi")
                    if any(
                        permission.module == module_name
                        and permission.resource == resource
                        and (
                            not self.tool_allowlist
                            or tool in self.tool_allowlist
                        )
                        and tool not in self.tool_denylist
                        for tool, permission in (
                            READ_TOOL_PERMISSIONS.items()
                        )
                    )
                },
            }
            for module_name in module_names
        ]
        actions = [
            {
                "action": action,
                "resource": WRITE_ACTION_RESOURCES[action],
                "scopes": sorted(WRITE_ACTION_SCOPES[action]),
            }
            for action in sorted(self.enabled_write_actions)
        ]
        return {
            "profile": self.profile.value,
            "effective_scopes": list(self.scopes),
            "effective_resources": {
                "graph": list(self.scopes),
                "powerbi": list(self.powerbi_scopes),
            },
            "module_scope_reasons": modules if self.profile is Profile.READ else [],
            "write_action_scope_reasons": actions if self.profile is Profile.WRITE else [],
            "resource_apis": [
                "https://graph.microsoft.com",
                *(
                    ["https://api.powerbi.com"]
                    if self.powerbi_scopes
                    else []
                ),
            ],
            "admin_must_preconsent_permissions": (
                self.permission_grant_mode == "admin_preconsented"
            ),
            "server_can_grant_permissions_or_consent": False,
            "private_api_scope_required": False,
            "policy_digest": self.policy_digest,
        }
