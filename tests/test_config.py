from __future__ import annotations

import pytest
from pydantic import ValidationError

from m365_secure_mcp.config import Profile, Settings

from .conftest import CLIENT_ID, TENANT_ID, USER_ID

APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
CONDITIONAL_ACCESS_POLICY_ID = "66666666-6666-4666-8666-666666666666"


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "token_cache_mode": "memory",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_default_is_minimal_read_profile() -> None:
    settings = make_settings()
    assert settings.profile is Profile.READ
    assert [module.value for module in settings.enabled_modules] == ["profile"]
    assert settings.scopes == ("User.Read",)
    assert settings.write_enabled is False


def test_placeholder_uuid_is_rejected() -> None:
    with pytest.raises(ValidationError, match="placeholder UUID"):
        make_settings(tenant_id="00000000-0000-0000-0000-000000000000")


def test_device_code_fails_closed() -> None:
    with pytest.raises(ValidationError, match="device-code flow is blocked"):
        make_settings(auth_flow="device_code")


def test_device_code_requires_explicit_opt_in() -> None:
    settings = make_settings(auth_flow="device_code", allow_device_code=True)
    assert settings.auth_flow == "device_code"


def test_write_profile_requires_two_gates() -> None:
    with pytest.raises(ValidationError, match="M365_WRITE_ENABLED"):
        make_settings(profile="write", write_actions="calendar.create_event")
    with pytest.raises(ValidationError, match="M365_WRITE_ACTIONS"):
        make_settings(profile="write", write_enabled=True)


def test_mail_writes_require_recipient_domain_allowlist() -> None:
    with pytest.raises(ValidationError, match="M365_ALLOWED_RECIPIENT_DOMAINS"):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="mail.create_draft",
        )


def test_write_scopes_derive_only_from_actions() -> None:
    settings = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="mail.create_draft",
        allowed_recipient_domains="example.com",
    )
    assert settings.scopes == ("Mail.ReadWrite", "User.Read")


@pytest.mark.parametrize(
    ("module", "message"),
    [
        ("sites", "M365_ALLOWED_SITE_IDS"),
        ("teams", "M365_ALLOWED_TEAM_IDS"),
        ("planner", "M365_ALLOWED_PLAN_IDS"),
        ("groups", "M365_ALLOWED_GROUP_IDS"),
    ],
)
def test_sensitive_modules_require_resource_allowlists(module: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        make_settings(modules=f"profile,{module}")


def test_planner_read_is_least_privileged() -> None:
    settings = make_settings(
        modules="profile,planner",
        allowed_plan_ids="plan-1",
    )
    assert settings.scopes == ("Tasks.Read", "User.Read")


def test_planner_details_write_uses_only_tasks_readwrite() -> None:
    settings = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="planner.update_task_details",
        allowed_plan_ids="plan-1",
    )
    assert settings.scopes == ("Tasks.ReadWrite", "User.Read")


def test_domains_are_bare_lowercase_dns_names() -> None:
    with pytest.raises(ValidationError, match="lowercase bare DNS"):
        make_settings(allowed_upn_domains="HTTPS://Example.com")


def test_principal_uuid_allowlist_is_normalized() -> None:
    settings = make_settings(allowed_user_object_ids=USER_ID.upper())
    assert settings.allowed_user_ids == frozenset({USER_ID})


def test_privileged_modules_require_second_gate() -> None:
    with pytest.raises(ValidationError, match="M365_PRIVILEGED_MODULES_ENABLED"):
        make_settings(modules="profile,security")
    settings = make_settings(
        modules="profile,security",
        privileged_modules_enabled=True,
    )
    assert "SecurityIncident.Read.All" in settings.scopes


def test_tool_allowlist_and_denylist_cannot_overlap() -> None:
    with pytest.raises(ValidationError, match="both enabled and disabled"):
        make_settings(
            enabled_tools="m365_list_users",
            disabled_tools="m365_list_users",
        )


def test_exact_read_tool_allowlist_reduces_teams_scopes() -> None:
    settings = make_settings(
        modules="profile,teams",
        allowed_team_ids="team-1",
        enabled_tools="m365_list_team_channels",
    )
    assert settings.scopes == ("Channel.ReadBasic.All", "User.Read")


def test_full_teams_module_has_permissions_for_each_fixed_contract() -> None:
    settings = make_settings(
        modules="profile,teams",
        allowed_team_ids="team-1",
    )
    assert {
        "Team.ReadBasic.All",
        "Channel.ReadBasic.All",
        "ChannelMember.Read.All",
        "ChannelMessage.Read.All",
        "Chat.ReadBasic",
        "Chat.Read",
        "User.Read",
    } == set(settings.scopes)


def test_tool_denylist_removes_unneeded_privileged_scope() -> None:
    settings = make_settings(
        modules="profile,security",
        privileged_modules_enabled=True,
        disabled_tools="m365_list_security_alerts",
    )
    assert "SecurityIncident.Read.All" in settings.scopes
    assert "SecurityAlert.Read.All" not in settings.scopes


def test_teams_writes_require_resource_allowlists() -> None:
    with pytest.raises(ValidationError, match="M365_ALLOWED_TEAM_IDS"):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="teams.send_channel_message",
        )
    with pytest.raises(ValidationError, match="M365_ALLOWED_CHAT_IDS"):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="teams.send_chat_message",
        )


def test_entra_read_tools_require_exact_resource_allowlists() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_APPLICATION_IDS",
    ):
        make_settings(
            modules="profile,entra_apps",
            enabled_tools="m365_get_application",
            privileged_modules_enabled=True,
        )
    application_settings = make_settings(
        modules="profile,entra_apps",
        enabled_tools="m365_get_application",
        allowed_application_ids=APPLICATION_ID,
        privileged_modules_enabled=True,
    )
    assert application_settings.scopes == (
        "Application.Read.All",
        "User.Read",
    )

    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_SERVICE_PRINCIPAL_IDS",
    ):
        make_settings(
            modules="profile,entra_apps",
            enabled_tools="m365_get_service_principal",
            privileged_modules_enabled=True,
        )


def test_privileged_writes_require_gate_scope_and_resource_allowlist() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_PRIVILEGED_WRITES_ENABLED",
    ):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="entra.update_application",
            allowed_application_ids=APPLICATION_ID,
        )
    settings = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="entra.update_application",
        allowed_application_ids=APPLICATION_ID,
        privileged_writes_enabled=True,
    )
    assert settings.scopes == ("Application.ReadWrite.All", "User.Read")

    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_CONDITIONAL_ACCESS_POLICY_IDS",
    ):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="governance.update_conditional_access_policy",
            privileged_writes_enabled=True,
        )
    conditional_access = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="governance.update_conditional_access_policy",
        allowed_conditional_access_policy_ids=(
            CONDITIONAL_ACCESS_POLICY_ID
        ),
        privileged_writes_enabled=True,
    )
    assert conditional_access.scopes == (
        "Policy.Read.All",
        "Policy.ReadWrite.ConditionalAccess",
        "User.Read",
    )


def test_entra_allowlists_accept_only_uuid_object_ids() -> None:
    with pytest.raises(ValidationError, match="invalid UUID"):
        make_settings(allowed_application_ids="not-an-object-id")
    settings = make_settings(
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
    )
    assert settings.application_ids == frozenset({APPLICATION_ID})
    assert settings.service_principal_ids == frozenset(
        {SERVICE_PRINCIPAL_ID}
    )


def test_agent_security_posture_contains_counts_not_private_identifiers() -> None:
    settings = make_settings(
        allowed_user_object_ids=USER_ID,
        allowed_upn_domains="private.example",
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
        allowed_conditional_access_policy_ids=(
            CONDITIONAL_ACCESS_POLICY_ID
        ),
    )
    summary = str(settings.agent_summary())
    assert TENANT_ID not in summary
    assert CLIENT_ID not in summary
    assert USER_ID not in summary
    assert APPLICATION_ID not in summary
    assert SERVICE_PRINCIPAL_ID not in summary
    assert CONDITIONAL_ACCESS_POLICY_ID not in summary
    assert "private.example" not in summary
    assert settings.agent_summary()[
        "entra_application_allowlist_count"
    ] == 1
