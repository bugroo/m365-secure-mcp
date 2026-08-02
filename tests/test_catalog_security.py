from __future__ import annotations

from types import SimpleNamespace

import pytest

from m365_secure_mcp.catalog import (
    SPECS,
    ReadSpec,
    _apply_policies,
    _filter_items,
)
from m365_secure_mcp.config import Settings
from m365_secure_mcp.models import CatalogReadInput
from m365_secure_mcp.permissions import READ_TOOL_PERMISSIONS
from m365_secure_mcp.security import SecurityError, SecurityPolicy

from .conftest import CLIENT_ID, TENANT_ID

APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
SERVICE_PRINCIPAL_ID = "55555555-5555-4555-8555-555555555555"
EDISCOVERY_CASE_ID = "88888888-8888-4888-8888-888888888888"
RETENTION_LABEL_ID = "99999999-9999-4999-8999-999999999999"


def _services() -> SimpleNamespace:
    settings = Settings(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        token_cache_mode="memory",  # noqa: S106
        allowed_application_ids=APPLICATION_ID,
        allowed_service_principal_ids=SERVICE_PRINCIPAL_ID,
        allowed_ediscovery_case_ids=EDISCOVERY_CASE_ID,
        allowed_retention_label_ids=RETENTION_LABEL_ID,
    )
    return SimpleNamespace(
        settings=settings,
        policy=SecurityPolicy(settings),
    )


def _spec(name: str) -> ReadSpec:
    return next(spec for spec in SPECS if spec.name == name)


def test_entra_object_reads_enforce_local_uuid_allowlists() -> None:
    services = _services()
    _apply_policies(
        _spec("m365_get_application"),
        CatalogReadInput(application_id=APPLICATION_ID),
        services,
    )
    with pytest.raises(SecurityError, match="not allowlisted"):
        _apply_policies(
            _spec("m365_get_application"),
            CatalogReadInput(
                application_id="77777777-7777-4777-8777-777777777777"
            ),
            services,
        )


def test_entra_inventory_filters_out_every_non_allowlisted_object() -> None:
    services = _services()
    items = [
        {"id": APPLICATION_ID, "displayName": "Allowed"},
        {
            "id": "77777777-7777-4777-8777-777777777777",
            "displayName": "Blocked",
        },
    ]
    filtered = _filter_items(
        _spec("m365_list_allowed_applications"),
        items,
        services,
    )
    assert filtered == [{"id": APPLICATION_ID, "displayName": "Allowed"}]


def test_license_endpoints_do_not_send_unsupported_top_parameter() -> None:
    for name in ("m365_list_subscribed_skus", "m365_list_domains"):
        spec = _spec(name)
        assert spec.supports_top is False


def test_presence_and_todo_avoid_rejected_graph_query_options() -> None:
    presence = _spec("m365_get_my_presence")
    assert presence.select is None
    assert presence.supports_top is False

    todo_lists = _spec("m365_list_todo_lists")
    assert todo_lists.select is None
    assert todo_lists.supports_top is True


def test_directory_role_reads_avoid_rejected_graph_query_options() -> None:
    definitions = _spec("m365_list_directory_role_definitions")
    assert definitions.supports_top is False

    assignments = _spec("m365_list_directory_role_assignments")
    assert assignments.select == (
        "id,principalId,roleDefinitionId,directoryScopeId"
    )
    assert "appScopeId" not in assignments.select


def test_service_communications_use_distinct_least_privileged_scopes() -> None:
    assert READ_TOOL_PERMISSIONS["m365_list_service_health"].scopes == frozenset(
        {"ServiceHealth.Read.All"}
    )
    assert READ_TOOL_PERMISSIONS["m365_list_service_issues"].scopes == frozenset(
        {"ServiceHealth.Read.All"}
    )
    assert READ_TOOL_PERMISSIONS["m365_list_service_messages"].scopes == frozenset(
        {"ServiceMessage.Read.All"}
    )


def test_compliance_reads_fail_closed_and_avoid_unsupported_query_parameters() -> None:
    services = _services()
    _apply_policies(
        _spec("m365_get_ediscovery_case"),
        CatalogReadInput(ediscovery_case_id=EDISCOVERY_CASE_ID),
        services,
    )
    _apply_policies(
        _spec("m365_get_retention_label"),
        CatalogReadInput(retention_label_id=RETENTION_LABEL_ID),
        services,
    )
    with pytest.raises(SecurityError, match="not allowlisted"):
        _apply_policies(
            _spec("m365_get_retention_label"),
            CatalogReadInput(
                retention_label_id="77777777-7777-4777-8777-777777777777"
            ),
            services,
        )
    retention = _spec("m365_list_allowed_retention_labels")
    assert retention.select is None
    assert retention.supports_top is False
