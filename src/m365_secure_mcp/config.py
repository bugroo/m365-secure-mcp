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
    GROUPS = "groups"
    ORGANIZATION = "organization"
    ONENOTE = "onenote"
    EXCEL = "excel"
    PEOPLE = "people"
    PRESENCE = "presence"
    SECURITY = "security"
    AUDIT = "audit"
    INTUNE = "intune"
    SERVICE_HEALTH = "service_health"


READ_SCOPES: dict[Module, frozenset[str]] = {
    Module.PROFILE: frozenset({"User.Read"}),
    Module.MAIL: frozenset({"Mail.Read"}),
    Module.CALENDAR: frozenset({"Calendars.Read"}),
    Module.FILES: frozenset({"Files.Read"}),
    Module.SITES: frozenset({"Sites.Selected"}),
    Module.CONTACTS: frozenset({"Contacts.Read"}),
    Module.TODO: frozenset({"Tasks.Read"}),
    Module.PLANNER: frozenset({"Tasks.Read"}),
    Module.TEAMS: frozenset({"ChannelMessage.Read.All", "Chat.Read"}),
    Module.DIRECTORY: frozenset({"User.ReadBasic.All"}),
    Module.GROUPS: frozenset({"GroupMember.Read.All"}),
    Module.ORGANIZATION: frozenset({"Organization.Read.All"}),
    Module.ONENOTE: frozenset({"Notes.Read"}),
    Module.EXCEL: frozenset({"Files.Read"}),
    Module.PEOPLE: frozenset({"People.Read"}),
    Module.PRESENCE: frozenset({"Presence.Read"}),
    Module.SECURITY: frozenset({"SecurityAlert.Read.All", "SecurityIncident.Read.All"}),
    Module.AUDIT: frozenset({"AuditLog.Read.All"}),
    Module.INTUNE: frozenset(
        {
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementManagedDevices.Read.All",
        }
    ),
    Module.SERVICE_HEALTH: frozenset({"ServiceHealth.Read.All"}),
}

PRIVILEGED_MODULES = frozenset(
    {
        Module.ORGANIZATION,
        Module.SECURITY,
        Module.AUDIT,
        Module.INTUNE,
        Module.SERVICE_HEALTH,
    }
)

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
}

KNOWN_WRITE_ACTIONS = frozenset(WRITE_ACTION_SCOPES)


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
    profile: Profile = Profile.READ
    modules: str = "profile"

    allowed_user_object_ids: str = ""
    allowed_upn_domains: str = ""
    allowed_site_ids: str = ""
    allowed_sharepoint_hosts: str = ""
    allowed_team_ids: str = ""
    allowed_chat_ids: str = ""
    allowed_group_ids: str = ""
    allowed_plan_ids: str = ""
    allowed_recipient_domains: str = ""

    auth_flow: Literal["interactive", "device_code"] = "interactive"
    allow_device_code: bool = False
    token_cache_mode: Literal["keyring", "memory"] = "keyring"  # noqa: S105
    keyring_service: str = Field(default="m365-secure-mcp", min_length=3, max_length=100)

    write_enabled: bool = False
    write_actions: str = ""
    privileged_modules_enabled: bool = False
    enabled_tools: str = ""
    disabled_tools: str = ""

    graph_timeout_seconds: float = Field(default=20.0, ge=3.0, le=60.0)
    graph_max_retries: int = Field(default=3, ge=0, le=5)
    max_items: int = Field(default=50, ge=1, le=100)
    max_response_bytes: int = Field(default=2_000_000, ge=64_000, le=10_000_000)
    max_tool_characters: int = Field(default=24_000, ge=4_000, le=50_000)
    max_text_file_bytes: int = Field(default=512_000, ge=1_024, le=2_000_000)
    audit_log_path: Path | None = None
    idempotency_db_path: Path | None = None
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

    @model_validator(mode="after")
    def validate_security_posture(self) -> Settings:
        module_names = set(_csv(self.modules))
        unknown_modules = module_names - {module.value for module in Module}
        if unknown_modules:
            raise ValueError(f"unknown M365 modules: {sorted(unknown_modules)}")
        if not module_names:
            raise ValueError("at least one M365 module must be enabled")
        if Module.SITES.value in module_names and not self.site_ids:
            raise ValueError("sites module requires M365_ALLOWED_SITE_IDS")
        if Module.TEAMS.value in module_names and not self.team_ids:
            raise ValueError("teams module requires M365_ALLOWED_TEAM_IDS")
        if Module.PLANNER.value in module_names and not self.plan_ids:
            raise ValueError("planner module requires M365_ALLOWED_PLAN_IDS")
        if Module.GROUPS.value in module_names and not self.group_ids:
            raise ValueError("groups module requires M365_ALLOWED_GROUP_IDS")
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

        if self.profile is Profile.WRITE:
            if not self.write_enabled:
                raise ValueError("write profile requires M365_WRITE_ENABLED=true")
            if not actions:
                raise ValueError("write profile requires an explicit M365_WRITE_ACTIONS allowlist")

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

        enabled_tools = set(_csv(self.enabled_tools))
        disabled_tools = set(_csv(self.disabled_tools))
        for tool_name in enabled_tools | disabled_tools:
            if not re.fullmatch(r"m365_[a-z0-9_]{3,96}", tool_name):
                raise ValueError("tool allowlists accept only explicit m365_* tool names")
        overlap = enabled_tools & disabled_tools
        if overlap:
            raise ValueError(f"tools cannot be both enabled and disabled: {sorted(overlap)}")
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
    def plan_ids(self) -> frozenset[str]:
        return frozenset(_csv(self.allowed_plan_ids))

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
            for module in self.enabled_modules:
                scopes.update(READ_SCOPES[module])
        else:
            for action in self.enabled_write_actions:
                scopes.update(WRITE_ACTION_SCOPES[action])
        return tuple(sorted(scopes))

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def cache_username(self) -> str:
        return f"{self.tenant_id}:{self.client_id}:{self.profile.value}"

    @property
    def effective_audit_log_path(self) -> Path:
        if self.audit_log_path is not None:
            return self.audit_log_path.expanduser()
        return (
            Path.home()
            / "Library"
            / "Logs"
            / "m365-secure-mcp"
            / f"audit-{self.profile.value}.jsonl"
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
            / f"idempotency-{self.profile.value}.sqlite3"
        )

    def public_summary(self) -> dict[str, object]:
        """Return a configuration summary that never includes credentials or tokens."""

        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "profile": self.profile.value,
            "modules": sorted(module.value for module in self.enabled_modules),
            "scopes": list(self.scopes),
            "principal_object_id_allowlist_configured": bool(self.allowed_user_ids),
            "upn_domain_allowlist": sorted(self.upn_domains),
            "site_allowlist_count": len(self.site_ids),
            "sharepoint_host_allowlist": sorted(self.sharepoint_hosts),
            "team_allowlist_count": len(self.team_ids),
            "chat_allowlist_count": len(self.chat_ids),
            "group_allowlist_count": len(self.group_ids),
            "planner_plan_allowlist_count": len(self.plan_ids),
            "privileged_modules_enabled": self.privileged_modules_enabled,
            "explicit_tool_allowlist": sorted(self.tool_allowlist),
            "explicit_tool_denylist": sorted(self.tool_denylist),
            "write_enabled": self.write_enabled,
            "write_actions": sorted(self.enabled_write_actions),
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
            "profile": self.profile.value,
            "modules": sorted(module.value for module in self.enabled_modules),
            "scopes": list(self.scopes),
            "allowed_user_ids": sorted(self.allowed_user_ids),
            "upn_domains": sorted(self.upn_domains),
            "site_ids": sorted(self.site_ids),
            "sharepoint_hosts": sorted(self.sharepoint_hosts),
            "team_ids": sorted(self.team_ids),
            "chat_ids": sorted(self.chat_ids),
            "group_ids": sorted(self.group_ids),
            "plan_ids": sorted(self.plan_ids),
            "recipient_domains": sorted(self.recipient_domains),
            "auth_flow": self.auth_flow,
            "allow_device_code": self.allow_device_code,
            "token_cache_mode": self.token_cache_mode,
            "write_enabled": self.write_enabled,
            "write_actions": sorted(self.enabled_write_actions),
            "privileged_modules_enabled": self.privileged_modules_enabled,
            "tool_allowlist": sorted(self.tool_allowlist),
            "tool_denylist": sorted(self.tool_denylist),
            "graph_timeout_seconds": self.graph_timeout_seconds,
            "graph_max_retries": self.graph_max_retries,
            "max_items": self.max_items,
            "max_response_bytes": self.max_response_bytes,
            "max_tool_characters": self.max_tool_characters,
            "max_text_file_bytes": self.max_text_file_bytes,
            "write_rate_limit_per_minute": self.write_rate_limit_per_minute,
            "idempotency_pending_seconds": self.idempotency_pending_seconds,
            "audit_log_path": str(self.effective_audit_log_path),
            "idempotency_db_path": str(self.effective_idempotency_db_path),
        }

    def permission_explanation(self) -> dict[str, object]:
        """Explain exactly why each effective delegated scope is requested."""

        modules = [
            {
                "module": module.value,
                "scopes": sorted(READ_SCOPES[module]),
            }
            for module in sorted(self.enabled_modules, key=lambda item: item.value)
        ]
        actions = [
            {
                "action": action,
                "scopes": sorted(WRITE_ACTION_SCOPES[action]),
            }
            for action in sorted(self.enabled_write_actions)
        ]
        return {
            "profile": self.profile.value,
            "effective_scopes": list(self.scopes),
            "module_scope_reasons": modules if self.profile is Profile.READ else [],
            "write_action_scope_reasons": actions if self.profile is Profile.WRITE else [],
            "resource_api": "https://graph.microsoft.com",
            "private_api_scope_required": False,
            "policy_digest": self.policy_digest,
        }
