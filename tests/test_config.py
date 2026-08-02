from __future__ import annotations

import pytest
from pydantic import ValidationError

from m365_secure_mcp.config import Profile, Settings
from m365_secure_mcp.security import SecurityError, SecurityPolicy

from .conftest import CLIENT_ID, TENANT_ID, USER_ID

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
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_default_is_minimal_read_profile() -> None:
    settings = make_settings()
    assert settings.profile is Profile.READ
    assert [module.value for module in settings.enabled_modules] == ["profile"]
    assert settings.scopes == ("User.Read",)
    assert settings.write_enabled is False
    assert settings.permission_grant_mode == "admin_preconsented"


def test_external_approval_broker_requires_both_paths_and_write_process(
    tmp_path,
) -> None:
    with pytest.raises(ValidationError, match="requires both"):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="mail.create_draft",
            allowed_recipient_domains="example.com",
            approval_broker_dir=tmp_path / "approval",
        )
    with pytest.raises(ValidationError, match="only in a write process"):
        make_settings(
            approval_broker_dir=tmp_path / "approval",
            approval_public_key_path=tmp_path / "approval.pub",
        )


def test_dynamic_user_consent_is_not_a_supported_mode() -> None:
    with pytest.raises(ValidationError, match="admin_preconsented"):
        make_settings(permission_grant_mode="dynamic")


def test_customer_deployment_requires_exact_principal_binding() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_USER_OBJECT_IDS",
    ):
        make_settings(deployment_kind="customer")
    settings = make_settings(
        deployment_kind="customer",
        allowed_user_object_ids=USER_ID,
    )
    assert settings.deployment_kind == "customer"
    assert settings.cache_username != make_settings().cache_username


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
        ("users_admin", "M365_ALLOWED_TARGET_USER_IDS"),
        ("directory_devices", "M365_ALLOWED_DEVICE_IDS"),
        ("windows365", "M365_ALLOWED_CLOUDPC_IDS"),
        ("compliance", "M365_ALLOWED_EDISCOVERY_CASE_IDS"),
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


def test_planner_assignees_are_separate_from_operator_principals() -> None:
    settings = make_settings(
        allowed_user_object_ids=USER_ID,
        allowed_planner_assignee_ids=RESOURCE_ID,
    )
    policy = SecurityPolicy(settings)
    assert policy.authorize_assignee(RESOURCE_ID) == RESOURCE_ID
    with pytest.raises(SecurityError, match="Planner assignee"):
        policy.authorize_assignee(USER_ID)


def test_privileged_modules_require_second_gate() -> None:
    with pytest.raises(ValidationError, match="M365_PRIVILEGED_MODULES_ENABLED"):
        make_settings(modules="profile,security")
    settings = make_settings(
        modules="profile,security",
        privileged_modules_enabled=True,
    )
    assert "SecurityIncident.Read.All" in settings.scopes


def test_service_communications_use_endpoint_specific_scopes() -> None:
    health = make_settings(
        modules="profile,service_health",
        enabled_tools="m365_list_service_health,m365_list_service_issues",
        privileged_modules_enabled=True,
    )
    assert health.scopes == ("ServiceHealth.Read.All", "User.Read")

    messages = make_settings(
        modules="profile,service_health",
        enabled_tools="m365_list_service_messages",
        privileged_modules_enabled=True,
    )
    assert messages.scopes == ("ServiceMessage.Read.All", "User.Read")

    complete = make_settings(
        modules="profile,service_health",
        privileged_modules_enabled=True,
    )
    assert complete.scopes == (
        "ServiceHealth.Read.All",
        "ServiceMessage.Read.All",
        "User.Read",
    )


def test_assurance_requires_signed_governance_and_exact_read_scopes() -> None:
    with pytest.raises(ValidationError, match="M365_GOVERNANCE_POLICY_PATH"):
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_identity_governance_posture",
        )
    settings = make_settings(
        modules="profile,assurance",
        privileged_modules_enabled=True,
        enabled_tools="m365_get_entra_identity_governance_posture",
        governance_policy_path="/private/governance-policy.signed.json",
        governance_public_key_path="/private/governance-policy.pub",
    )
    assert settings.scopes == (
        "Policy.Read.All",
        "RoleManagement.Read.Directory",
        "User.Read",
    )
    assert settings.write_enabled is False


def test_permission_grant_drift_requires_exact_targets_and_scope() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_SERVICE_PRINCIPAL_IDS",
    ):
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_permission_grant_drift",
            governance_policy_path="/private/governance-policy.signed.json",
            governance_public_key_path="/private/governance-policy.pub",
        )
    settings = make_settings(
        modules="profile,assurance",
        privileged_modules_enabled=True,
        enabled_tools="m365_get_entra_permission_grant_drift",
        allowed_service_principal_ids=RESOURCE_ID,
        governance_policy_path="/private/governance-policy.signed.json",
        governance_public_key_path="/private/governance-policy.pub",
    )
    assert settings.scopes == (
        "Directory.Read.All",
        "User.Read",
    )


def test_profile_debt_requires_current_app_target_fence_and_exact_scope() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_SERVICE_PRINCIPAL_IDS",
    ):
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_profile_debt_posture",
            governance_policy_path="/private/governance-policy.signed.json",
            governance_public_key_path="/private/governance-policy.pub",
        )
    settings = make_settings(
        modules="profile,assurance",
        privileged_modules_enabled=True,
        enabled_tools="m365_get_entra_profile_debt_posture",
        allowed_service_principal_ids=RESOURCE_ID,
        governance_policy_path="/private/governance-policy.signed.json",
        governance_public_key_path="/private/governance-policy.pub",
    )
    assert settings.scopes == (
        "Directory.Read.All",
        "User.Read",
    )


def test_application_credential_posture_requires_exact_targets_and_scope() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_APPLICATION_IDS",
    ):
        make_settings(
            modules="profile,assurance",
            privileged_modules_enabled=True,
            enabled_tools="m365_get_entra_app_credential_posture",
            governance_policy_path="/private/governance-policy.signed.json",
            governance_public_key_path="/private/governance-policy.pub",
        )
    settings = make_settings(
        modules="profile,assurance",
        privileged_modules_enabled=True,
        enabled_tools="m365_get_entra_app_credential_posture",
        allowed_application_ids=APPLICATION_ID,
        governance_policy_path="/private/governance-policy.signed.json",
        governance_public_key_path="/private/governance-policy.pub",
    )
    assert settings.scopes == (
        "Application.Read.All",
        "User.Read",
    )


def test_workload_readiness_requires_both_fences_and_exact_scope_union() -> None:
    common = {
        "modules": "profile,assurance",
        "privileged_modules_enabled": True,
        "enabled_tools": "m365_get_entra_workload_identity_readiness",
        "governance_policy_path": "/private/governance-policy.signed.json",
        "governance_public_key_path": "/private/governance-policy.pub",
    }
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_APPLICATION_IDS",
    ):
        make_settings(
            **common,
            allowed_service_principal_ids=RESOURCE_ID,
        )
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_SERVICE_PRINCIPAL_IDS",
    ):
        make_settings(
            **common,
            allowed_application_ids=APPLICATION_ID,
        )

    settings = make_settings(
        **common,
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=RESOURCE_ID,
    )
    assert settings.scopes == (
        "Application.Read.All",
        "Directory.Read.All",
        "User.Read",
    )
    assert settings.write_enabled is False


def test_compliance_reads_require_exact_resource_allowlists() -> None:
    with pytest.raises(
        ValidationError,
        match="M365_ALLOWED_RETENTION_LABEL_IDS",
    ):
        make_settings(
            modules="profile,compliance",
            enabled_tools="m365_get_retention_label",
            privileged_modules_enabled=True,
        )
    settings = make_settings(
        modules="profile,compliance",
        allowed_ediscovery_case_ids=EDISCOVERY_CASE_ID,
        allowed_retention_label_ids=RETENTION_LABEL_ID,
        privileged_modules_enabled=True,
    )
    assert settings.scopes == (
        "RecordsManagement.Read.All",
        "User.Read",
        "eDiscovery.Read.All",
    )
    policy = SecurityPolicy(settings)
    assert (
        policy.authorize_ediscovery_case(EDISCOVERY_CASE_ID)
        == EDISCOVERY_CASE_ID
    )
    assert (
        policy.authorize_retention_label(RETENTION_LABEL_ID)
        == RETENTION_LABEL_ID
    )


def test_powerbi_uses_a_separate_oauth_resource() -> None:
    settings = make_settings(
        modules="profile,powerbi",
        enabled_tools="m365_get_powerbi_dataset",
        allowed_powerbi_workspace_ids=RESOURCE_ID,
        allowed_powerbi_dataset_ids=RESOURCE_ID,
        privileged_modules_enabled=True,
    )
    assert settings.scopes == ("User.Read",)
    assert settings.powerbi_scopes == (
        "https://analysis.windows.net/powerbi/api/Dataset.Read.All",
    )


def test_office_content_modules_require_exact_item_allowlists() -> None:
    with pytest.raises(ValidationError, match="M365_ALLOWED_DRIVE_IDS"):
        make_settings(modules="profile,word")
    word = make_settings(
        modules="profile,word",
        allowed_drive_ids="drive-1",
        allowed_word_item_ids="word-1",
    )
    assert word.scopes == ("Files.Read", "User.Read")


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


@pytest.mark.parametrize(
    ("action", "allowlists"),
    [
        (
            "groups.update",
            {"allowed_group_ids": RESOURCE_ID},
        ),
    ],
)
def test_user_and_group_administration_require_privileged_write_gate(
    action: str,
    allowlists: dict[str, str],
) -> None:
    with pytest.raises(
        ValidationError,
        match="M365_PRIVILEGED_WRITES_ENABLED",
    ):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions=action,
            **allowlists,
        )


def test_operational_profile_update_is_bounded_t1_not_privileged_write() -> None:
    with pytest.raises(ValidationError, match="M365_GOVERNANCE_POLICY_PATH"):
        make_settings(
            profile="write",
            write_enabled=True,
            write_actions="entra.user.operational_profile.update",
            allowed_target_user_ids=RESOURCE_ID,
        )
    settings = make_settings(
        profile="write",
        write_enabled=True,
        write_actions="entra.user.operational_profile.update",
        allowed_target_user_ids=RESOURCE_ID,
        governance_policy_path="/private/governance-policy.signed.json",
        governance_public_key_path="/private/governance-policy.pub",
    )
    assert settings.scopes == (
        "GroupMember.Read.All",
        "RoleManagement.Read.Directory",
        "User.Read",
        "User.ReadUpdate.All",
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
        allowed_planner_assignee_ids=RESOURCE_ID,
        allowed_upn_domains="private.example",
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
        allowed_conditional_access_policy_ids=(
            CONDITIONAL_ACCESS_POLICY_ID
        ),
        allowed_ediscovery_case_ids=EDISCOVERY_CASE_ID,
        allowed_retention_label_ids=RETENTION_LABEL_ID,
    )
    summary = str(settings.agent_summary())
    assert TENANT_ID not in summary
    assert CLIENT_ID not in summary
    assert USER_ID not in summary
    assert RESOURCE_ID not in summary
    assert APPLICATION_ID not in summary
    assert SERVICE_PRINCIPAL_ID not in summary
    assert CONDITIONAL_ACCESS_POLICY_ID not in summary
    assert EDISCOVERY_CASE_ID not in summary
    assert RETENTION_LABEL_ID not in summary
    assert "private.example" not in summary
    assert settings.agent_summary()[
        "entra_application_allowlist_count"
    ] == 1
    assert settings.agent_summary()["ediscovery_case_allowlist_count"] == 1
    assert settings.agent_summary()["retention_label_allowlist_count"] == 1
